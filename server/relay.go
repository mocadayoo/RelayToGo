package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	proto "RelayToGo/protocol"

	"github.com/quic-go/quic-go"
)

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
	return nil
}

func (s *relayServer) rollbackMappingsLocked(a *agent, tunnels []proto.Mapping) {
	for _, t := range tunnels {
		if r := s.tcp[t.PublicPort]; r != nil && r.agent == a {
			_ = r.ln.Close()
			delete(s.tcp, t.PublicPort)
		}
		if r := s.udp[t.PublicPort]; r != nil && r.agent == a {
			_ = r.conn.Close()
			delete(s.udp, t.PublicPort)
		}
	}
}

func (s *relayServer) openTCP(a *agent, t proto.Mapping) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", t.PublicPort))
	if err != nil {
		return err
	}

	r := &tcpRelay{t.PublicPort, a, ln}
	s.tcp[t.PublicPort] = r
	go s.acceptTCP(r)
	return nil
}

func (s *relayServer) openUDP(a *agent, t proto.Mapping) error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(t.PublicPort)})
	if err != nil {
		return err
	}

	r := &udpRelay{port: t.PublicPort, agent: a, conn: conn, flows: map[string]*udpFlow{}, byID: map[uint64]*udpFlow{}}
	s.udp[t.PublicPort] = r
	go s.acceptUDP(r)
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

func (s *relayServer) deleteTunnel(id string) (bool, error) {
	s.mu.Lock()
	for i := range s.cfg.Agents {
		for _, t := range s.cfg.Agents[i].Tunnels {
			if t.ID == id {
				agentID := s.cfg.Agents[i].ID
				s.mu.Unlock()
				return s.deleteTunnelForAgent(agentID, id)
			}
		}
	}
	s.mu.Unlock()
	return false, nil
}

func (s *relayServer) deleteTunnelForAgent(agentID, id string) (bool, error) {
	s.mu.Lock()
	var tunnel proto.Mapping
	found := false
	for i := range s.cfg.Agents {
		if s.cfg.Agents[i].ID != agentID {
			continue
		}
		for j, t := range s.cfg.Agents[i].Tunnels {
			if t.ID != id {
				continue
			}
			tunnel, found = t, true
			s.cfg.Agents[i].Tunnels = append(s.cfg.Agents[i].Tunnels[:j], s.cfg.Agents[i].Tunnels[j+1:]...)
			break
		}
	}
	if !found {
		s.mu.Unlock()
		return false, nil
	}
	if r := s.tcp[tunnel.PublicPort]; r != nil {
		_ = r.ln.Close()
		delete(s.tcp, tunnel.PublicPort)
	}
	if r := s.udp[tunnel.PublicPort]; r != nil {
		_ = r.conn.Close()
		delete(s.udp, tunnel.PublicPort)
	}
	if a := s.agents[agentID]; a != nil {
		_ = a.send(proto.Message{Type: proto.MsgTunnelRemove, TunnelID: id})
	}
	s.mu.Unlock()
	if err := s.saveConfig(); err != nil {
		return true, err
	}
	return true, nil
}

func (s *relayServer) removeLocked(a *agent) {
	delete(s.agents, a.id)

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
