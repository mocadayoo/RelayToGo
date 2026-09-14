package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	proto "RelayToGo/protocol"

	"github.com/quic-go/quic-go"
)

type udpSession struct {
	conn   *net.UDPConn
	port   uint16
	flowID uint64
}

type relayAgent struct {
	conn            *quic.Conn
	relayPublicAddr string
	tcp             map[uint16]string
	udp             map[uint16]string
	tunnels         map[string]proto.Mapping
	stats           map[string]*tunnelStats
	mu              sync.Mutex
	sessions        map[string]*udpSession
	lastPong        atomic.Int64
}

func main() {
	server := flag.String("server", "127.0.0.1:40000", "server QUIC address")
	id := flag.String("id", "", "agent identifier")
	token := flag.String("token", "", "agent token")
	flag.Parse()
	if *id == "" || *token == "" {
		log.Fatal("-id and -token are required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	q, err := quic.DialAddr(ctx, *server, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"RelayToGo"},
	}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		log.Fatal(err)
	}

	defer q.CloseWithError(0, "shutdown")
	control, err := q.OpenStreamSync(ctx)
	if err != nil {
		log.Fatal(err)
	}

	enc, dec := json.NewEncoder(control), json.NewDecoder(control)
	if err := enc.Encode(proto.Message{Type: proto.MsgRegister, AgentID: *id, Token: *token}); err != nil {
		log.Fatal("send registration")
	}

	var reply proto.Message
	if err := dec.Decode(&reply); err != nil {
		log.Fatal("read assignment")
	}

	if reply.Type != proto.MsgRegistered {
		log.Fatalf("registration rejected: %s", reply.Reason)
	}

	a := &relayAgent{conn: q, relayPublicAddr: reply.RelayPublicAddr, tcp: map[uint16]string{}, udp: map[uint16]string{}, tunnels: map[string]proto.Mapping{}, stats: map[string]*tunnelStats{}, sessions: map[string]*udpSession{}}
	for _, t := range reply.Mappings {
		key := string(t.Network) + fmt.Sprintf(":%d", t.PublicPort)
		a.tunnels[key] = t
		a.stats[key] = &tunnelStats{}
		if t.Network == proto.NetworkTCP || t.Network == proto.NetworkBoth {
			a.tcp[t.PublicPort] = t.TargetAddr
		}
		if t.Network == proto.NetworkUDP || t.Network == proto.NetworkBoth {
			a.udp[t.PublicPort] = t.TargetAddr
		}
	}
	a.lastPong.Store(time.Now().UnixNano())
	go a.runPanel(ctx)
	go a.receiveUDP(ctx)
	go a.heartbeat(ctx, control, enc, dec)
	log.Printf("attached: %d tunnel(s)", len(reply.Mappings))
	for {
		st, err := q.AcceptStream(ctx)
		if err != nil {
			return
		}

		go a.handleTCP(st)
	}
}

func (a *relayAgent) handleTCP(st *quic.Stream) {
	defer st.Close()
	var p uint16
	if err := binary.Read(st, binary.BigEndian, &p); err != nil {
		return
	}

	target := a.tcp[p]
	if target == "" {
		return
	}

	local, err := net.Dial("tcp", target)
	if err != nil {
		st.CancelRead(1)
		st.CancelWrite(1)
		return
	}

	defer local.Close()
	stats := a.statsFor(proto.NetworkTCP, p)
	stats.addClient(1)
	defer stats.addClient(-1)

	done := make(chan struct{})
	go func() {
		if _, err := io.Copy(local, countedReader{Reader: st, count: stats.addIn}); err != nil {
			st.CancelRead(1)
		}

		if tcp, ok := local.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}

		close(done)
	}()
	if _, err := io.Copy(st, countedReader{Reader: local, count: stats.addOut}); err != nil {
		st.CancelWrite(1)
	} else {
		_ = st.Close()
	}

	<-done
}

func (a *relayAgent) heartbeat(ctx context.Context, control *quic.Stream, enc *json.Encoder, dec *json.Decoder) {
	pongs := make(chan struct{}, 1)
	go func() {
		for {
			var message proto.Message
			if err := dec.Decode(&message); err != nil {
				return
			}

			if message.Type != proto.MsgPong {
				continue
			}

			a.lastPong.Store(time.Now().UnixNano())
			select {
			case pongs <- struct{}{}:
			default:
			}
		}
	}()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := enc.Encode(proto.Message{Type: proto.MsgPing}); err != nil {
				return
			}

			select {
			case <-pongs:
			case <-time.After(10 * time.Second):
				_ = control.Close()
				return
			}
		}
	}
}

func (a *relayAgent) receiveUDP(ctx context.Context) {
	for {
		d, err := a.conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}

		p, flowID, payload, err := proto.UnmarshalUDPDatagram(d)
		if err != nil || a.udp[p] == "" {
			continue
		}

		a.toLocalUDP(p, flowID, payload)
	}
}

func (a *relayAgent) toLocalUDP(port uint16, flowID uint64, payload []byte) {
	a.statsFor(proto.NetworkUDP, port).addIn(len(payload))

	key := fmt.Sprintf("%d:%d", port, flowID)
	a.mu.Lock()
	s := a.sessions[key]
	if s == nil {
		target, e := net.ResolveUDPAddr("udp", a.udp[port])
		if e == nil {
			c, e := net.DialUDP("udp", nil, target)
			if e == nil {
				s = &udpSession{conn: c, port: port, flowID: flowID}
				a.sessions[key] = s
				a.statsFor(proto.NetworkUDP, port).addClient(1)
				go a.fromLocalUDP(key, s)
			}
		}
	}
	a.mu.Unlock()
	if s != nil {
		_, _ = s.conn.Write(payload)
	}
}

func (a *relayAgent) fromLocalUDP(key string, s *udpSession) {
	b := make([]byte, 65535)
	for {
		s.conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		n, e := s.conn.Read(b)
		if e != nil {
			a.mu.Lock()
			if a.sessions[key] == s {
				delete(a.sessions, key)
				a.statsFor(proto.NetworkUDP, s.port).addClient(-1)
			}
			a.mu.Unlock()
			_ = s.conn.Close()
			return
		}

		d, e := proto.MarshalUDPDatagram(s.port, s.flowID, b[:n])
		if e == nil {
			a.statsFor(proto.NetworkUDP, s.port).addOut(n)
			_ = a.conn.SendDatagram(d)
		}
	}
}
