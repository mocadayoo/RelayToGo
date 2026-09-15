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

const controlSendTimeout = 10 * time.Second

type controlWriter struct {
	mu               sync.Mutex
	enc              *json.Encoder
	setWriteDeadline func(time.Time) error
}

func (w *controlWriter) send(ctx context.Context, message proto.Message) error {
	deadline := time.Now().Add(controlSendTimeout)
	if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
		deadline = requested
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.setWriteDeadline(deadline); err != nil {
		return err
	}
	err := w.enc.Encode(message)
	_ = w.setWriteDeadline(time.Time{})
	return err
}

func (a *relayAgent) controlLoop(ctx context.Context, dec *json.Decoder, writer *controlWriter) {
	defer a.conn.CloseWithError(0, "control stream ended")
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
				if writer.send(ctx, proto.Message{Type: proto.MsgTunnelAck, TunnelID: message.TunnelID, Reason: "missing tunnel"}) != nil {
					return
				}
				continue
			}
			a.addTunnel(*message.Tunnel)
			logging.Event("+", "tunnel %s added: %s %d -> %s", message.Tunnel.ID, message.Tunnel.Network, message.Tunnel.PublicPort, message.Tunnel.TargetAddr)
			if writer.send(ctx, proto.Message{Type: proto.MsgTunnelAck, TunnelID: message.Tunnel.ID}) != nil {
				return
			}
		case proto.MsgTunnelRemove:
			a.mu.Lock()
			tunnel := a.tunnels[message.TunnelID]
			a.mu.Unlock()
			a.removeTunnel(message.TunnelID)
			logging.Event("-", "tunnel %s deleted: %s %d -> %s", message.TunnelID, tunnel.Network, tunnel.PublicPort, tunnel.TargetAddr)
			if writer.send(ctx, proto.Message{Type: proto.MsgTunnelAck, TunnelID: message.TunnelID}) != nil {
				return
			}
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
	if err := a.control.send(ctx, message); err != nil {
		_ = a.conn.CloseWithError(0, "control write failed")
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
		a.tcp[tunnel.PublicPort] = tunnel
	case proto.NetworkUDP:
		a.udp[tunnel.PublicPort] = tunnel
	case proto.NetworkBoth:
		a.tcp[tunnel.PublicPort] = tunnel
		a.udp[tunnel.PublicPort] = tunnel
	}
}

func (a *relayAgent) removeTunnel(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	tunnel, ok := a.tunnels[id]
	if !ok {
		return
	}

	for key, session := range a.sessions {
		if session.port != tunnel.PublicPort || session.mappingID != tunnel.MappingID {
			continue
		}
		delete(a.sessions, key)
		_ = session.conn.Close()
		session.stats.addClient(-1)
	}
	for key := range a.pendingSessions {
		if key.port == tunnel.PublicPort && key.mappingID == tunnel.MappingID {
			delete(a.pendingSessions, key)
		}
	}
	for key := range a.retryAfter {
		if key.port == tunnel.PublicPort && key.mappingID == tunnel.MappingID {
			delete(a.retryAfter, key)
		}
	}
	delete(a.tunnels, id)
	delete(a.stats, tunnelKey(tunnel.Network, tunnel.PublicPort))
	if (tunnel.Network == proto.NetworkTCP || tunnel.Network == proto.NetworkBoth) && a.tcp[tunnel.PublicPort].MappingID == tunnel.MappingID {
		delete(a.tcp, tunnel.PublicPort)
	}
	if (tunnel.Network == proto.NetworkUDP || tunnel.Network == proto.NetworkBoth) && a.udp[tunnel.PublicPort].MappingID == tunnel.MappingID {
		delete(a.udp, tunnel.PublicPort)
	}
}

func tunnelKey(network proto.Network, port uint16) string {
	return string(network) + fmt.Sprintf(":%d", port)
}
