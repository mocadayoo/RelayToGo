package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"RelayToGo/internal/logging"
	proto "RelayToGo/protocol"

	"github.com/quic-go/quic-go"
)

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

	ac, ok := s.auth(m, conn)
	if !ok {
		logging.Event("!", "agent connection rejected")
		_ = enc.Encode(proto.Message{Type: proto.MsgError, Reason: "authentication failed"})
		return
	}

	a := &agent{id: ac.ID, conn: conn, outbound: make(chan proto.Message, 32), done: make(chan struct{}), acks: map[string]chan proto.Message{}, operations: make(chan proto.Message, 64)}
	go a.sendLoop(enc)
	go s.operationLoop(a)
	s.mu.Lock()
	previous := s.agents[a.id]
	if previous != nil {
		s.removeLocked(previous)
	}
	s.mu.Unlock()
	if previous != nil {
		previous.stop()
		_ = previous.conn.CloseWithError(0, "replaced by a new connection")
	}

	if err = s.register(a, ac.Tunnels); err != nil {
		_ = a.send(proto.Message{Type: proto.MsgError, Reason: err.Error()})
		a.stop()
		return
	}

	s.mu.Lock()
	s.agents[a.id] = a
	s.mu.Unlock()
	logging.Event("+", "agent %s connected with %d tunnel(s)", a.id, len(ac.Tunnels))

	defer func() {
		a.stop()
		s.remove(a)
		logging.Event("-", "agent %s disconnected", a.id)
	}()
	if !a.send(proto.Message{Type: proto.MsgRegistered, Mappings: ac.Tunnels, RelayPublicAddr: s.cfg.PublicAddr}) {
		return
	}

	go s.fromAgentUDP(ctx, a)
	for {
		var msg proto.Message
		_ = control.SetReadDeadline(time.Now().Add(45 * time.Second))

		if dec.Decode(&msg) != nil {
			return
		}
		switch msg.Type {
		case proto.MsgPing:
			if !a.send(proto.Message{Type: proto.MsgPong}) {
				return
			}
		case proto.MsgClose:
			return
		case proto.MsgTunnelAck:
			a.completeAck(msg)
			if msg.Reason != "" {
				logging.Event("!", "agent %s rejected tunnel %s: %s", a.id, msg.TunnelID, msg.Reason)
			}
		case proto.MsgTunnelCreate:
			a.enqueueOperation(msg)
		case proto.MsgTunnelDelete:
			a.enqueueOperation(msg)
		}
	}
}

func (a *agent) enqueueOperation(msg proto.Message) {
	select {
	case <-a.done:
		return
	case a.operations <- msg:
	default:
		_ = a.trySend(proto.Message{Type: proto.MsgTunnelResult, RequestID: msg.RequestID, TunnelID: msg.TunnelID, Reason: "too many pending tunnel operations"})
	}
}

func (s *relayServer) operationLoop(a *agent) {
	for {
		select {
		case <-a.done:
			return
		case msg := <-a.operations:
			switch msg.Type {
			case proto.MsgTunnelCreate:
				s.handleTunnelCreate(a, msg)
			case proto.MsgTunnelDelete:
				s.handleTunnelDelete(a, msg)
			}
		}
	}
}

func (s *relayServer) handleTunnelCreate(a *agent, msg proto.Message) {
	if msg.Tunnel == nil {
		_ = a.send(proto.Message{Type: proto.MsgTunnelResult, RequestID: msg.RequestID, Reason: "missing tunnel"})
		return
	}
	tunnel, err := s.createTunnel(a.id, *msg.Tunnel)
	if err != nil {
		_ = a.send(proto.Message{Type: proto.MsgTunnelResult, RequestID: msg.RequestID, Reason: err.Error()})
		return
	}
	_ = a.send(proto.Message{Type: proto.MsgTunnelResult, RequestID: msg.RequestID, Tunnel: &tunnel, TunnelID: tunnel.ID})
}

func (s *relayServer) handleTunnelDelete(a *agent, msg proto.Message) {
	deleted, err := s.deleteTunnelForAgent(a.id, msg.TunnelID)
	result := proto.Message{Type: proto.MsgTunnelResult, RequestID: msg.RequestID, TunnelID: msg.TunnelID}
	if err != nil {
		result.Reason = err.Error()
	} else if !deleted {
		result.Reason = "tunnel not found"
	}
	_ = a.send(result)
}

func (a *agent) send(message proto.Message) bool {
	select {
	case <-a.done:
		return false
	case a.outbound <- message:
		return true
	}
}

func (a *agent) trySend(message proto.Message) bool {
	select {
	case <-a.done:
		return false
	case a.outbound <- message:
		return true
	default:
		return false
	}
}

func (a *agent) sendLoop(enc *json.Encoder) {
	defer a.stop()
	for {
		select {
		case <-a.done:
			return
		case message := <-a.outbound:
			if err := enc.Encode(message); err != nil {
				return
			}
		}
	}
}

func (a *agent) stop() { a.closeOnce.Do(func() { close(a.done) }) }

func (a *agent) sendAndWaitAck(message proto.Message) error {
	if message.TunnelID == "" {
		return fmt.Errorf("missing tunnel ID")
	}
	ack := make(chan proto.Message, 1)
	a.mu.Lock()
	if _, exists := a.acks[message.TunnelID]; exists {
		a.mu.Unlock()
		return fmt.Errorf("tunnel operation already pending")
	}
	a.acks[message.TunnelID] = ack
	a.mu.Unlock()
	defer func() { a.mu.Lock(); delete(a.acks, message.TunnelID); a.mu.Unlock() }()
	if !a.send(message) {
		return fmt.Errorf("control channel unavailable")
	}
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case result := <-ack:
		if result.Reason != "" {
			return errors.New(result.Reason)
		}
		return nil
	case <-a.done:
		return fmt.Errorf("control channel closed")
	case <-timer.C:
		return fmt.Errorf("acknowledgement timeout")
	}
}

func (a *agent) completeAck(message proto.Message) {
	a.mu.Lock()
	ack := a.acks[message.TunnelID]
	a.mu.Unlock()
	if ack != nil {
		select {
		case ack <- message:
		default:
		}
	}
}

func (s *relayServer) auth(m proto.Message, conn *quic.Conn) (agentConfig, bool) {
	if m.Type != proto.MsgRegister {
		return agentConfig{}, false
	}
	state := conn.ConnectionState().TLS
	if len(state.PeerCertificates) != 1 {
		return agentConfig{}, false
	}
	fingerprint, err := certificateFingerprint(state.PeerCertificates[0].Raw)
	if err != nil {
		return agentConfig{}, false
	}
	return s.agentByFingerprint(fingerprint)
}
