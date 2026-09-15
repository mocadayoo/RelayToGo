package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"RelayToGo/internal/logging"
	proto "RelayToGo/protocol"

	"github.com/quic-go/quic-go"
)

const relaySetupTimeout = 10 * time.Second

func (s *relayServer) register(a *agent, ts []proto.Mapping) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range ts {
		switch t.Network {
		case proto.NetworkTCP:
			if s.tcp[t.PublicPort] != nil {
				return fmt.Errorf("TCP port %d active", t.PublicPort)
			}
		case proto.NetworkUDP:
			if s.udp[t.PublicPort] != nil {
				return fmt.Errorf("UDP port %d active", t.PublicPort)
			}
		case proto.NetworkBoth:
			if s.tcp[t.PublicPort] != nil || s.udp[t.PublicPort] != nil {
				return fmt.Errorf("both port %d active", t.PublicPort)
			}
		default:
			return fmt.Errorf("unknown network %q", t.Network)
		}
	}
	for _, t := range ts {
		switch t.Network {
		case proto.NetworkTCP:
			if err := s.openTCP(a, t); err != nil {
				s.rollbackMappingsLocked(a, ts)
				return err
			}
		case proto.NetworkUDP:
			if err := s.openUDP(a, t); err != nil {
				s.rollbackMappingsLocked(a, ts)
				return err
			}
		case proto.NetworkBoth:
			if err := s.openTCP(a, t); err != nil {
				s.rollbackMappingsLocked(a, ts)
				return err
			}
			if err := s.openUDP(a, t); err != nil {
				s.rollbackMappingsLocked(a, ts)
				return err
			}
		}
	}
	s.publishUDPSnapshotLocked()
	return nil
}

func (s *relayServer) rollbackMappingsLocked(a *agent, tunnels []proto.Mapping) {
	for _, t := range tunnels {
		if (t.Network == proto.NetworkTCP || t.Network == proto.NetworkBoth) && matchingTCPRelay(s.tcp[t.PublicPort], a, t.MappingID) {
			r := s.tcp[t.PublicPort]
			r.close()
			delete(s.tcp, t.PublicPort)
		}
		if (t.Network == proto.NetworkUDP || t.Network == proto.NetworkBoth) && matchingUDPRelay(s.udp[t.PublicPort], a, t.MappingID) {
			r := s.udp[t.PublicPort]
			r.close()
			delete(s.udp, t.PublicPort)
		}
	}
	s.publishUDPSnapshotLocked()
}

func matchingTCPRelay(r *tcpRelay, a *agent, mappingID uint64) bool {
	return r != nil && r.agent == a && r.tunnel.MappingID == mappingID
}

func matchingUDPRelay(r *udpRelay, a *agent, mappingID uint64) bool {
	return r != nil && r.agent == a && r.tunnel.MappingID == mappingID
}

func (s *relayServer) openTCP(a *agent, t proto.Mapping) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", t.PublicPort))
	if err != nil {
		return err
	}

	r := &tcpRelay{tunnel: t, agent: a, ln: ln, conns: map[net.Conn]struct{}{}}
	s.tcp[t.PublicPort] = r
	go s.acceptTCP(r)
	return nil
}

func (s *relayServer) openUDP(a *agent, t proto.Mapping) error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(t.PublicPort)})
	if err != nil {
		return err
	}

	r := &udpRelay{tunnel: t, agent: a, conn: conn, flows: map[netip.AddrPort]*udpFlow{}, byID: map[uint64]*udpFlow{}, done: make(chan struct{})}
	s.udp[t.PublicPort] = r
	go s.acceptUDP(r)
	go r.pruneLoop()
	return nil
}

func (s *relayServer) acceptTCP(r *tcpRelay) {
	for {
		c, e := r.ln.Accept()
		if e != nil {
			return
		}
		if !r.addConn(c) {
			_ = c.Close()
			continue
		}
		logging.Event("+", "client %s connected to tunnel %s", c.RemoteAddr(), r.tunnel.ID)
		go relayTCP(r, c)
	}
}

func (r *tcpRelay) addConn(c net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	r.conns[c] = struct{}{}
	return true
}

func (r *tcpRelay) removeConn(c net.Conn) {
	r.mu.Lock()
	delete(r.conns, c)
	r.mu.Unlock()
}

func (r *tcpRelay) close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	_ = r.ln.Close()
	for c := range r.conns {
		_ = c.Close()
	}
	r.mu.Unlock()
}

func relayTCP(r *tcpRelay, c net.Conn) {
	client := c.RemoteAddr().String()
	defer logging.Event("-", "client %s disconnected from tunnel %s", client, r.tunnel.ID)
	defer r.removeConn(c)
	defer c.Close()
	openCtx, cancel := context.WithTimeout(context.Background(), relaySetupTimeout)
	defer cancel()
	st, e := r.agent.conn.OpenStreamSync(openCtx)
	if e != nil {
		return
	}

	defer st.Close()
	_ = st.SetWriteDeadline(time.Now().Add(relaySetupTimeout))
	if err := binary.Write(st, binary.BigEndian, r.tunnel.PublicPort); err != nil {
		st.CancelWrite(1)
		return
	}
	if err := binary.Write(st, binary.BigEndian, r.tunnel.MappingID); err != nil {
		st.CancelWrite(1)
		return
	}
	_ = st.SetWriteDeadline(time.Time{})

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
	} else if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
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
		if flowID == 0 {
			continue
		}
		d, e := proto.MarshalUDPDatagram(r.tunnel.PublicPort, r.tunnel.MappingID, flowID, b[:n])
		if e == nil {
			r.sendDatagram(d)
		}
	}
}

func (r *udpRelay) sendDatagram(datagram []byte) {
	if maximum := r.agent.maxDatagramSize.Load(); maximum > 0 && int64(len(datagram)) > maximum {
		r.recordDrop("exceeds negotiated QUIC datagram size")
		return
	}
	if err := r.agent.conn.SendDatagram(datagram); err != nil {
		var tooLarge *quic.DatagramTooLargeError
		if errors.As(err, &tooLarge) {
			r.agent.maxDatagramSize.Store(tooLarge.MaxDatagramPayloadSize)
			r.recordDrop("exceeds negotiated QUIC datagram size")
			return
		}
		r.recordDrop("QUIC datagram send failed")
	}
}

func (r *udpRelay) recordDrop(reason string) {
	count := r.dropped.Add(1)
	// Log at powers of two: observable without turning a packet flood into a log flood.
	if count == 1 || count&(count-1) == 0 {
		logging.Event("!", "UDP datagram dropped for tunnel %s (%s; total=%d)", r.tunnel.ID, reason, count)
	}
}

func (s *relayServer) fromAgentUDP(ctx context.Context, a *agent) {
	for {
		d, e := a.conn.ReceiveDatagram(ctx)
		if e != nil {
			return
		}
		p, mappingID, flowID, pay, e := proto.UnmarshalUDPDatagram(d)
		if e != nil {
			continue
		}
		r := s.udpSnapshot.Load().(map[uint16]*udpRelay)[p]
		if r == nil || r.agent != a || r.tunnel.MappingID != mappingID {
			continue
		}
		r.mu.Lock()
		flow := r.byID[flowID]
		if flow != nil {
			flow.lastSeen = time.Now()
		}
		r.mu.Unlock()
		if flow != nil {
			_, _ = r.conn.WriteToUDP(pay, net.UDPAddrFromAddrPort(flow.address))
		}
	}
}

func (r *udpRelay) flowID(address *net.UDPAddr) uint64 {
	addr, ok := netip.AddrFromSlice(address.IP)
	if !ok {
		return 0
	}
	key := netip.AddrPortFrom(addr.Unmap(), uint16(address.Port))
	r.mu.Lock()
	defer r.mu.Unlock()
	if flow := r.flows[key]; flow != nil {
		flow.lastSeen = time.Now()
		return flow.id
	}

	r.nextFlowID++
	flow := &udpFlow{id: r.nextFlowID, address: key, lastSeen: time.Now()}
	r.flows[key], r.byID[flow.id] = flow, flow
	return flow.id
}

func (r *udpRelay) pruneLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.mu.Lock()
			r.pruneFlowsLocked()
			r.mu.Unlock()
		case <-r.done:
			return
		}
	}
}

func (r *udpRelay) close() {
	r.closeOnce.Do(func() {
		close(r.done)
		_ = r.conn.Close()
	})
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

func (s *relayServer) deleteTunnelForAgent(agentID, id string) (bool, error) {
	s.mu.Lock()
	var tunnel proto.Mapping
	found := false
	for i := range s.cfg.Agents {
		if s.cfg.Agents[i].ID != agentID {
			continue
		}
		for _, t := range s.cfg.Agents[i].Tunnels {
			if t.ID != id {
				continue
			}
			tunnel, found = t, true
			break
		}
	}
	if !found {
		s.mu.Unlock()
		return false, nil
	}
	a := s.agents[agentID]
	s.mu.Unlock()
	if a == nil {
		return true, fmt.Errorf("agent is not connected")
	}
	if err := a.sendAndWaitAck(proto.Message{Type: proto.MsgTunnelRemove, TunnelID: id}); err != nil {
		// The agent may have applied the deletion before its ACK became unavailable.
		// Keep the persisted desired state and force a reconnect, which replays it.
		s.disconnectAgent(a, "tunnel deletion acknowledgement failed")
		return true, fmt.Errorf("agent did not acknowledge deletion: %w", err)
	}
	s.mu.Lock()
	s.removeTunnelConfigLocked(agentID, id)
	s.mu.Unlock()
	if err := s.saveData(); err != nil {
		s.mu.Lock()
		for i := range s.cfg.Agents {
			if s.cfg.Agents[i].ID == agentID {
				s.cfg.Agents[i].Tunnels = append(s.cfg.Agents[i].Tunnels, tunnel)
				s.reserveTunnelLocked(tunnel)
				break
			}
		}
		s.mu.Unlock()
		if rollbackErr := a.sendAndWaitAck(proto.Message{Type: proto.MsgTunnelAdd, Tunnel: &tunnel, TunnelID: id}); rollbackErr != nil {
			logging.Event("!", "restore tunnel %s after save failure: %v", id, rollbackErr)
			s.disconnectAgent(a, "tunnel restore failed")
		}
		return true, err
	}
	s.mu.Lock()
	if (tunnel.Network == proto.NetworkTCP || tunnel.Network == proto.NetworkBoth) && matchingTCPRelay(s.tcp[tunnel.PublicPort], a, tunnel.MappingID) {
		r := s.tcp[tunnel.PublicPort]
		r.close()
		delete(s.tcp, tunnel.PublicPort)
	}
	if (tunnel.Network == proto.NetworkUDP || tunnel.Network == proto.NetworkBoth) && matchingUDPRelay(s.udp[tunnel.PublicPort], a, tunnel.MappingID) {
		r := s.udp[tunnel.PublicPort]
		r.close()
		delete(s.udp, tunnel.PublicPort)
	}
	s.publishUDPSnapshotLocked()
	s.mu.Unlock()
	logging.Event("-", "tunnel %s deleted from %s: %s %d -> %s", id, agentID, tunnel.Network, tunnel.PublicPort, tunnel.TargetAddr)
	return true, nil
}

func (s *relayServer) removeLocked(a *agent) {
	if s.agents[a.id] == a {
		delete(s.agents, a.id)
	}

	for p, r := range s.tcp {
		if r.agent == a {
			r.close()
			delete(s.tcp, p)
		}
	}
	for p, r := range s.udp {
		if r.agent == a {
			r.close()
			delete(s.udp, p)
		}
	}
	s.publishUDPSnapshotLocked()
}

func (s *relayServer) publishUDPSnapshotLocked() {
	snapshot := make(map[uint16]*udpRelay, len(s.udp))
	for port, relay := range s.udp {
		snapshot[port] = relay
	}
	s.udpSnapshot.Store(snapshot)
}
