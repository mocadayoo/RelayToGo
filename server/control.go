package main

import (
	"context"
	"encoding/json"
	"log"
	"time"

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
		_ = enc.Encode(proto.Message{Type: proto.MsgError, Reason: "authentication failed"})
		return
	}

	a := &agent{id: ac.ID, conn: conn, outbound: make(chan proto.Message, 32)}
	go a.sendLoop(enc)

	if err = s.register(a, ac.Tunnels); err != nil {
		_ = enc.Encode(proto.Message{Type: proto.MsgError, Reason: err.Error()})
		return
	}

	s.mu.Lock()
	s.agents[a.id] = a
	s.mu.Unlock()

	defer s.remove(a)
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
			log.Printf("agent %s acknowledged tunnel %s: %s", a.id, msg.TunnelID, msg.Reason)
		case proto.MsgTunnelCreate:
			if msg.Tunnel == nil {
				_ = a.send(proto.Message{Type: proto.MsgTunnelResult, RequestID: msg.RequestID, Reason: "missing tunnel"})
				continue
			}
			tunnel, err := s.createTunnel(a.id, *msg.Tunnel)
			if err != nil {
				_ = a.send(proto.Message{Type: proto.MsgTunnelResult, RequestID: msg.RequestID, Reason: err.Error()})
				continue
			}
			_ = a.send(proto.Message{Type: proto.MsgTunnelResult, RequestID: msg.RequestID, Tunnel: &tunnel, TunnelID: tunnel.ID})
		case proto.MsgTunnelDelete:
			deleted, err := s.deleteTunnelForAgent(a.id, msg.TunnelID)
			result := proto.Message{Type: proto.MsgTunnelResult, RequestID: msg.RequestID, TunnelID: msg.TunnelID}
			if err != nil {
				result.Reason = err.Error()
			} else if !deleted {
				result.Reason = "tunnel not found"
			}
			_ = a.send(result)
		}
	}
}

func (a *agent) send(message proto.Message) bool {
	select {
	case a.outbound <- message:
		return true
	default:
		return false
	}
}

func (a *agent) sendLoop(enc *json.Encoder) {
	for message := range a.outbound {
		if err := enc.Encode(message); err != nil {
			return
		}
	}
}

func (s *relayServer) notifyTunnelAdd(agentID string, tunnel proto.Mapping) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	agent := s.agents[agentID]
	if agent == nil {
		return false
	}

	return agent.send(proto.Message{Type: proto.MsgTunnelAdd, Tunnel: &tunnel, TunnelID: tunnel.ID})
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
