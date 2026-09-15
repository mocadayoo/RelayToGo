package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	proto "RelayToGo/protocol"
	"RelayToGo/internal/logging"

	"github.com/quic-go/quic-go"
)

const relaySetupTimeout = 10 * time.Second

const (
	udpSessionIdleTimeout = 2 * time.Minute
	udpSessionRetryDelay = 5 * time.Second
)

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
	now := time.Now()
	a.mu.Lock()
	tunnel, exists := a.udp[port]
	if !exists || tunnel.MappingID != mappingID {
		a.mu.Unlock()
		return
	}
	stats := a.statsForLocked(proto.NetworkUDP, port)
	if stats == nil {
		a.mu.Unlock()
		return
	}
	stats.addIn(len(payload))
	s := a.sessions[key]
	if s != nil {
		a.mu.Unlock()
		a.writeLocalUDP(s, payload)
		return
	}
	if retryAt, failed := a.retryAfter[key]; failed && now.Before(retryAt) {
		stats.addDrop()
		a.mu.Unlock()
		return
	}
	delete(a.retryAfter, key)
	if _, pending := a.pendingSessions[key]; pending {
		stats.addDrop()
		a.mu.Unlock()
		return
	}
	a.pendingSessions[key] = struct{}{}
	targetAddr := tunnel.TargetAddr
	a.mu.Unlock()

	dialCtx, cancel := context.WithTimeout(context.Background(), relaySetupTimeout)
	rawConn, err := (&net.Dialer{}).DialContext(dialCtx, "udp", targetAddr)
	cancel()
	var conn *net.UDPConn
	if err == nil {
		var ok bool
		conn, ok = rawConn.(*net.UDPConn)
		if !ok {
			_ = rawConn.Close()
			err = errors.New("UDP dial returned a non-UDP connection")
		}
	}

	a.mu.Lock()
	delete(a.pendingSessions, key)
	current, stillMapped := a.udp[port]
	if err != nil || !stillMapped || current.MappingID != mappingID {
		if err != nil && stillMapped && current.MappingID == mappingID {
			a.retryAfter[key] = time.Now().Add(udpSessionRetryDelay)
			stats.addDrop()
		}
		a.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		return
	}
	if s = a.sessions[key]; s == nil {
		s = &udpSession{conn: conn, port: port, mappingID: mappingID, flowID: flowID, stats: stats}
		a.sessions[key] = s
		stats.addClient(1)
		go a.fromLocalUDP(key, s)
	} else {
		_ = conn.Close()
	}
	a.mu.Unlock()
	a.writeLocalUDP(s, payload)
}

func (a *relayAgent) writeLocalUDP(s *udpSession, payload []byte) {
	// Keep the session alive for client-to-target traffic too. Without this,
	// one-way UDP traffic expires even while the public client is active.
	_ = s.conn.SetReadDeadline(time.Now().Add(udpSessionIdleTimeout))
	_, _ = s.conn.Write(payload)
}

func (a *relayAgent) fromLocalUDP(key udpSessionKey, s *udpSession) {
	b := udpBuffers.Get().([]byte)
	defer udpBuffers.Put(b)
	for {
		s.conn.SetReadDeadline(time.Now().Add(udpSessionIdleTimeout))
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
			a.sendUDPDatagram(s, d)
		}
	}
}

func (a *relayAgent) pruneUDPFailures(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			a.mu.Lock()
			for key, retryAt := range a.retryAfter {
				if !retryAt.After(now) {
					delete(a.retryAfter, key)
				}
			}
			a.mu.Unlock()
		}
	}
}

func (a *relayAgent) sendUDPDatagram(s *udpSession, datagram []byte) {
	if maximum := a.maxDatagramSize.Load(); maximum > 0 && int64(len(datagram)) > maximum {
		s.stats.addDrop()
		return
	}
	if err := a.conn.SendDatagram(datagram); err != nil {
		var tooLarge *quic.DatagramTooLargeError
		if errors.As(err, &tooLarge) {
			a.maxDatagramSize.Store(tooLarge.MaxDatagramPayloadSize)
		}
		count := s.stats.addDrop()
		if count == 1 || count&(count-1) == 0 {
			logging.Event("!", "UDP datagram dropped for tunnel port %d (%v; total=%d)", s.port, err, count)
		}
	}
}
