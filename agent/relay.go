package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	proto "RelayToGo/protocol"

	"github.com/quic-go/quic-go"
)

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
