package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	proto "RelayToGo/protocol"

	"github.com/quic-go/quic-go"
)

const relaySetupTimeout = 10 * time.Second

var udpBuffers = sync.Pool{New: func() any { return make([]byte, 65535) }}

func (a *relayAgent) handleTCP(st *quic.Stream) {
	defer st.Close()
	_ = st.SetReadDeadline(time.Now().Add(relaySetupTimeout))
	var p uint16
	if err := binary.Read(st, binary.BigEndian, &p); err != nil {
		return
	}
	var mappingID uint64
	if err := binary.Read(st, binary.BigEndian, &mappingID); err != nil {
		return
	}
	_ = st.SetReadDeadline(time.Time{})

	target, stats := a.tcpTargetAndStats(p, mappingID)
	if target == "" || stats == nil {
		return
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), relaySetupTimeout)
	defer cancel()
	local, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", target)
	if err != nil {
		st.CancelRead(1)
		st.CancelWrite(1)
		return
	}

	defer local.Close()
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

func (a *relayAgent) heartbeat(ctx context.Context, writer *controlWriter) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := writer.send(ctx, proto.Message{Type: proto.MsgPing}); err != nil {
				_ = a.conn.CloseWithError(0, "control heartbeat failed")
				return
			}
			if time.Since(time.Unix(0, a.lastPong.Load())) > 25*time.Second {
				_ = a.conn.CloseWithError(0, "control heartbeat timed out")
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

		p, mappingID, flowID, payload, err := proto.UnmarshalUDPDatagram(d)
		if err != nil || !a.hasUDP(p, mappingID) {
			continue
		}

		a.toLocalUDP(p, mappingID, flowID, payload)
	}
}

func (a *relayAgent) toLocalUDP(port uint16, mappingID, flowID uint64, payload []byte) {
	key := udpSessionKey{port: port, mappingID: mappingID, flowID: flowID}
	a.mu.Lock()
	stats := a.statsForLocked(proto.NetworkUDP, port)
	if stats == nil {
		a.mu.Unlock()
		return
	}
	stats.addIn(len(payload))
	s := a.sessions[key]
	if s == nil {
		tunnel, exists := a.udp[port]
		if !exists || tunnel.MappingID != mappingID {
			a.mu.Unlock()
			return
		}
		target, e := net.ResolveUDPAddr("udp", tunnel.TargetAddr)
		if e == nil {
			c, e := net.DialUDP("udp", nil, target)
			if e == nil {
				s = &udpSession{conn: c, port: port, mappingID: mappingID, flowID: flowID, stats: stats}
				a.sessions[key] = s
				stats.addClient(1)
				go a.fromLocalUDP(key, s)
			}
		}
	}
	a.mu.Unlock()
	if s != nil {
		// Keep the session alive for client-to-target traffic too. Without this,
		// one-way UDP traffic expires even while the public client is active.
		_ = s.conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		_, _ = s.conn.Write(payload)
	}
}

func (a *relayAgent) fromLocalUDP(key udpSessionKey, s *udpSession) {
	b := udpBuffers.Get().([]byte)
	defer udpBuffers.Put(b)
	for {
		s.conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		n, e := s.conn.Read(b)
		if e != nil {
			a.mu.Lock()
			if a.sessions[key] == s {
				delete(a.sessions, key)
				s.stats.addClient(-1)
			}
			a.mu.Unlock()
			_ = s.conn.Close()
			return
		}

		d, e := proto.MarshalUDPDatagram(s.port, s.mappingID, s.flowID, b[:n])
		if e == nil {
			s.stats.addOut(n)
			_ = a.conn.SendDatagram(d)
		}
	}
}
