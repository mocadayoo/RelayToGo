package main

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	proto "RelayToGo/protocol"
	temp "RelayToGo/temp"

	"github.com/quic-go/quic-go"
)

type config struct {
	QUICAddr   string        `json:"quic_addr"`
	PublicAddr string        `json:"public_addr"`
	Agents     []agentConfig `json:"agents"`
}

type agentConfig struct {
	ID      string          `json:"id"`
	Token   string          `json:"token"`
	Tunnels []proto.Mapping `json:"tunnels"`
}

type agent struct {
	id   string
	conn *quic.Conn
}

type tcpRelay struct {
	port  uint16
	agent *agent
	ln    net.Listener
}

type udpRelay struct {
	port       uint16
	agent      *agent
	conn       *net.UDPConn
	mu         sync.Mutex
	nextFlowID uint64
	flows      map[string]*udpFlow
	byID       map[uint64]*udpFlow
}

type udpFlow struct {
	id       uint64
	address  *net.UDPAddr
	lastSeen time.Time
}

type relayServer struct {
	mu  sync.Mutex
	cfg config
	tcp map[uint16]*tcpRelay
	udp map[uint16]*udpRelay
}

func main() {
	path := flag.String("config", "server/config.json", "server configuration")
	flag.Parse()
	cfg, err := loadConfig(*path)
	if err != nil {
		log.Fatal(err)
	}

	tlsConf, err := temp.GenerateTLSConfig()
	if err != nil {
		log.Fatal(err)
	}

	addr, err := net.ResolveUDPAddr("udp", cfg.QUICAddr)
	if err != nil {
		log.Fatal(err)
	}

	sock, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
	}

	defer sock.Close()
	ln, err := quic.Listen(sock, tlsConf, &quic.Config{EnableDatagrams: true})
	if err != nil {
		log.Fatal(err)
	}

	defer ln.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s := &relayServer{cfg: cfg, tcp: map[uint16]*tcpRelay{}, udp: map[uint16]*udpRelay{}}
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}

			continue
		}
		go s.handleAgent(ctx, conn)
	}
}

func loadConfig(path string) (config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return config{}, err
	}

	var c config
	if err = json.Unmarshal(data, &c); err != nil {
		return c, err
	}

	if c.QUICAddr == "" {
		return c, errors.New("quic_addr is required")
	}
	if c.PublicAddr == "" {
		return c, errors.New("public_addr is required")
	}

	ids := map[string]bool{}
	tcp, udp := map[uint16]bool{}, map[uint16]bool{}
	for _, a := range c.Agents {
		if a.ID == "" || a.Token == "" || ids[a.ID] {
			return c, errors.New("agent id and token must be unique")
		}
		ids[a.ID] = true
		tunnelNames := map[string]bool{}
		for _, t := range a.Tunnels {
			if t.Name == "" || tunnelNames[t.Name] {
				return c, fmt.Errorf("agent %s tunnel names must be unique", a.ID)
			}

			tunnelNames[t.Name] = true

			if t.PublicPort == 0 {
				return c, errors.New("public_port is required")
			}
			if _, _, e := net.SplitHostPort(t.TargetAddr); e != nil {
				return c, e
			}
			if t.Network == proto.NetworkTCP {
				if tcp[t.PublicPort] {
					return c, fmt.Errorf("duplicate TCP port %d", t.PublicPort)
				}
				tcp[t.PublicPort] = true
			} else if t.Network == proto.NetworkUDP {
				if udp[t.PublicPort] {
					return c, fmt.Errorf("duplicate UDP port %d", t.PublicPort)
				}
				udp[t.PublicPort] = true
			} else if t.Network == proto.NetworkBoth {
				if tcp[t.PublicPort] || udp[t.PublicPort] {
					return c, fmt.Errorf("duplicate both port %d", t.PublicPort)
				}

				tcp[t.PublicPort], udp[t.PublicPort] = true, true
			} else {
				return c, errors.New("network must be tcp, udp, or both")
			}
		}
	}
	return c, nil
}

func (s *relayServer) handleAgent(ctx context.Context, conn *quic.Conn) {
	control, err := conn.AcceptStream(ctx)
	if err != nil {
		return
	}

	dec, enc := json.NewDecoder(control), json.NewEncoder(control)
	var m proto.Message
	if err := dec.Decode(&m); err != nil {
		return
	}

	ac, ok := s.auth(m)
	if !ok {
		_ = enc.Encode(proto.Message{Type: proto.MsgError, Reason: "authentication failed"})
		return
	}

	a := &agent{id: ac.ID, conn: conn}
	if err = s.register(a, ac.Tunnels); err != nil {
		_ = enc.Encode(proto.Message{Type: proto.MsgError, Reason: err.Error()})
		return
	}

	defer s.remove(a)
	if err := enc.Encode(proto.Message{Type: proto.MsgRegistered, Mappings: ac.Tunnels, RelayPublicAddr: s.cfg.PublicAddr}); err != nil {
		return
	}

	go s.fromAgentUDP(ctx, a)
	for {
		var msg proto.Message
		_ = control.SetReadDeadline(time.Now().Add(45 * time.Second))

		if dec.Decode(&msg) != nil {
			return
		}
		if msg.Type == proto.MsgPing {
			if enc.Encode(proto.Message{Type: proto.MsgPong}) != nil {
				return
			}
		}
	}
}

func (s *relayServer) auth(m proto.Message) (agentConfig, bool) {
	if m.Type != proto.MsgRegister {
		return agentConfig{}, false
	}
	for _, a := range s.cfg.Agents {
		if a.ID == m.AgentID && subtle.ConstantTimeCompare([]byte(a.Token), []byte(m.Token)) == 1 {
			return a, true
		}
	}
	return agentConfig{}, false
}

func (s *relayServer) register(a *agent, ts []proto.Mapping) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range ts {
		if t.Network == proto.NetworkTCP || t.Network == proto.NetworkBoth {
			if s.tcp[t.PublicPort] != nil {
				return fmt.Errorf("TCP port %d active", t.PublicPort)
			}
		}
		if t.Network == proto.NetworkUDP || t.Network == proto.NetworkBoth {
			if s.udp[t.PublicPort] != nil {
				return fmt.Errorf("UDP port %d active", t.PublicPort)
			}
		}
	}
	for _, t := range ts {
		if t.Network == proto.NetworkTCP || t.Network == proto.NetworkBoth {
			ln, e := net.Listen("tcp", fmt.Sprintf(":%d", t.PublicPort))
			if e != nil {
				s.removeLocked(a)
				return e
			}
			r := &tcpRelay{t.PublicPort, a, ln}
			s.tcp[t.PublicPort] = r
			go s.acceptTCP(r)
		}
		if t.Network == proto.NetworkUDP || t.Network == proto.NetworkBoth {
			c, e := net.ListenUDP("udp", &net.UDPAddr{Port: int(t.PublicPort)})
			if e != nil {
				s.removeLocked(a)
				return e
			}
			r := &udpRelay{port: t.PublicPort, agent: a, conn: c, flows: map[string]*udpFlow{}, byID: map[uint64]*udpFlow{}}
			s.udp[t.PublicPort] = r
			go s.acceptUDP(r)
		}
	}
	return nil
}

func (s *relayServer) acceptTCP(r *tcpRelay) {
	for {
		c, e := r.ln.Accept()
		if e != nil {
			return
		}
		go relayTCP(c, r.agent.conn, r.port)
	}
}

func relayTCP(c net.Conn, q *quic.Conn, p uint16) {
	defer c.Close()
	st, e := q.OpenStreamSync(context.Background())
	if e != nil {
		return
	}

	defer st.Close()
	if err := binary.Write(st, binary.BigEndian, p); err != nil {
		st.CancelWrite(1)
		return
	}

	done := make(chan struct{})
	go func() {
		if _, err := io.Copy(st, c); err != nil {
			st.CancelWrite(1)
		} else {
			_ = st.Close()
		}
		close(done)
	}()
	if _, err := io.Copy(c, st); err != nil {
		st.CancelRead(1)
	}

	<-done
}

func (s *relayServer) acceptUDP(r *udpRelay) {
	b := make([]byte, 65535)
	for {
		n, a, e := r.conn.ReadFromUDP(b)
		if e != nil {
			return
		}
		flowID := r.flowID(a)
		d, e := proto.MarshalUDPDatagram(r.port, flowID, b[:n])
		if e == nil {
			_ = r.agent.conn.SendDatagram(d)
		}
	}
}

func (s *relayServer) fromAgentUDP(ctx context.Context, a *agent) {
	for {
		d, e := a.conn.ReceiveDatagram(ctx)
		if e != nil {
			return
		}
		p, flowID, pay, e := proto.UnmarshalUDPDatagram(d)
		if e != nil {
			continue
		}
		s.mu.Lock()
		r := s.udp[p]
		s.mu.Unlock()
		if r == nil || r.agent != a {
			continue
		}
		r.mu.Lock()
		r.pruneFlowsLocked()
		flow := r.byID[flowID]
		if flow != nil {
			flow.lastSeen = time.Now()
		}
		r.mu.Unlock()
		if flow != nil {
			_, _ = r.conn.WriteToUDP(pay, flow.address)
		}
	}
}

func (r *udpRelay) flowID(address *net.UDPAddr) uint64 {
	key := address.String()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneFlowsLocked()
	if flow := r.flows[key]; flow != nil {
		flow.lastSeen = time.Now()
		return flow.id
	}

	r.nextFlowID++
	flow := &udpFlow{id: r.nextFlowID, address: address, lastSeen: time.Now()}
	r.flows[key], r.byID[flow.id] = flow, flow
	return flow.id
}

func (r *udpRelay) pruneFlowsLocked() {
	deadline := time.Now().Add(-2 * time.Minute)
	for key, flow := range r.flows {
		if flow.lastSeen.Before(deadline) {
			delete(r.flows, key)
			delete(r.byID, flow.id)
		}
	}
}

func (s *relayServer) remove(a *agent) { s.mu.Lock(); defer s.mu.Unlock(); s.removeLocked(a) }

func (s *relayServer) removeLocked(a *agent) {
	for p, r := range s.tcp {
		if r.agent == a {
			_ = r.ln.Close()
			delete(s.tcp, p)
		}
	}
	for p, r := range s.udp {
		if r.agent == a {
			_ = r.conn.Close()
			delete(s.udp, p)
		}
	}
}
