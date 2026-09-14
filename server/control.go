package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
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
		switch msg.Type {
		case proto.MsgPing:
			if enc.Encode(proto.Message{Type: proto.MsgPong}) != nil {
				return
			}
		case proto.MsgClose:
			return
		}
	}
}

func (s *relayServer) auth(m proto.Message) (agentConfig, bool) {
	switch m.Type {
	case proto.MsgRegister:
	default:
		return agentConfig{}, false
	}
	for _, a := range s.cfg.Agents {
		if a.ID == m.AgentID && subtle.ConstantTimeCompare([]byte(a.Token), []byte(m.Token)) == 1 {
			return a, true
		}
	}
	return agentConfig{}, false
}
