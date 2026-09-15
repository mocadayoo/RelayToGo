package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"RelayToGo/internal/logging"
	proto "RelayToGo/protocol"
)

type controlWriter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (w *controlWriter) send(message proto.Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enc.Encode(message)
}

func (a *relayAgent) controlLoop(ctx context.Context, dec *json.Decoder, writer *controlWriter) {
	for {
		var message proto.Message
		if err := dec.Decode(&message); err != nil {
			return
		}

		switch message.Type {
		case proto.MsgPong:
			a.lastPong.Store(time.Now().UnixNano())
		case proto.MsgTunnelAdd:
			if message.Tunnel == nil {
				_ = writer.send(proto.Message{Type: proto.MsgTunnelAck, TunnelID: message.TunnelID, Reason: "missing tunnel"})
				continue
			}
			a.addTunnel(*message.Tunnel)
			logging.Event("+", "tunnel %s added: %s %d -> %s", message.Tunnel.ID, message.Tunnel.Network, message.Tunnel.PublicPort, message.Tunnel.TargetAddr)
			_ = writer.send(proto.Message{Type: proto.MsgTunnelAck, TunnelID: message.Tunnel.ID})
		case proto.MsgTunnelRemove:
			a.mu.Lock()
			tunnel := a.tunnels[message.TunnelID]
			a.mu.Unlock()
			a.removeTunnel(message.TunnelID)
			logging.Event("-", "tunnel %s deleted: %s %d -> %s", message.TunnelID, tunnel.Network, tunnel.PublicPort, tunnel.TargetAddr)
			_ = writer.send(proto.Message{Type: proto.MsgTunnelAck, TunnelID: message.TunnelID})
		case proto.MsgTunnelResult:
			a.deliverResult(message)
		}
	}
}

func (a *relayAgent) deliverResult(message proto.Message) {
	a.mu.Lock()
	result := a.pending[message.RequestID]
	delete(a.pending, message.RequestID)
	a.mu.Unlock()
	if result != nil {
		result <- message
	}
}

func (a *relayAgent) requestTunnel(ctx context.Context, message proto.Message) (proto.Message, error) {
	if a.control == nil {
		return proto.Message{}, errors.New("relay control connection is unavailable")
	}
	requestID := fmt.Sprintf("ui-%d-%d", time.Now().UnixNano(), a.requestSeq.Add(1))
	result := make(chan proto.Message, 1)
	a.mu.Lock()
	a.pending[requestID] = result
	a.mu.Unlock()
	message.RequestID = requestID
	if err := a.control.send(message); err != nil {
		a.mu.Lock()
		delete(a.pending, requestID)
		a.mu.Unlock()
		return proto.Message{}, err
	}
	select {
	case response := <-result:
		if response.Reason != "" {
			return proto.Message{}, errors.New(response.Reason)
		}
		return response, nil
	case <-ctx.Done():
		a.mu.Lock()
		delete(a.pending, requestID)
		a.mu.Unlock()
		return proto.Message{}, ctx.Err()
	}
}

func (a *relayAgent) addTunnel(tunnel proto.Mapping) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tunnels[tunnel.ID] = tunnel
	a.stats[tunnelKey(tunnel.Network, tunnel.PublicPort)] = &tunnelStats{}
	switch tunnel.Network {
	case proto.NetworkTCP:
		a.tcp[tunnel.PublicPort] = tunnel.TargetAddr
	case proto.NetworkUDP:
		a.udp[tunnel.PublicPort] = tunnel.TargetAddr
	case proto.NetworkBoth:
		a.tcp[tunnel.PublicPort] = tunnel.TargetAddr
		a.udp[tunnel.PublicPort] = tunnel.TargetAddr
	}
}

func (a *relayAgent) removeTunnel(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	tunnel, ok := a.tunnels[id]
	if !ok {
		return
	}

	stats := a.stats[tunnelKey(tunnel.Network, tunnel.PublicPort)]
	for key, session := range a.sessions {
		if session.port != tunnel.PublicPort {
			continue
		}
		delete(a.sessions, key)
		_ = session.conn.Close()
		if stats != nil {
			stats.addClient(-1)
		}
	}
	delete(a.tunnels, id)
	delete(a.stats, tunnelKey(tunnel.Network, tunnel.PublicPort))
	delete(a.tcp, tunnel.PublicPort)
	delete(a.udp, tunnel.PublicPort)
}

func tunnelKey(network proto.Network, port uint16) string {
	return string(network) + fmt.Sprintf(":%d", port)
}
