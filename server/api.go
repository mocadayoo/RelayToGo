package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"

	"RelayToGo/internal/logging"
	proto "RelayToGo/protocol"
)

func (s *relayServer) createTunnel(agentID string, tunnel proto.Mapping) (proto.Mapping, error) {
	if tunnel.ID == "" {
		tunnel.ID = newTunnelID()
	}
	tunnel.PublicPort = 0
	tunnel.MappingID = newMappingID()
	if err := validateTunnel(tunnel); err != nil {
		return proto.Mapping{}, err
	}

	s.mu.Lock()
	agent := s.agents[agentID]
	for _, configured := range s.cfg.Agents {
		if configured.ID != agentID {
			continue
		}
		for _, existing := range configured.Tunnels {
			if existing.ID == tunnel.ID {
				s.mu.Unlock()
				return proto.Mapping{}, fmt.Errorf("tunnel ID already exists")
			}
			if existing.Name == tunnel.Name {
				s.mu.Unlock()
				return proto.Mapping{}, fmt.Errorf("tunnel name already exists")
			}
		}
	}
	s.mu.Unlock()
	if agent == nil {
		return proto.Mapping{}, fmt.Errorf("agent is not connected")
	}
	if err := s.registerTunnel(agent, &tunnel); err != nil {
		return proto.Mapping{}, err
	}
	s.mu.Lock()
	for i := range s.cfg.Agents {
		if s.cfg.Agents[i].ID == agentID {
			s.cfg.Agents[i].Tunnels = append(s.cfg.Agents[i].Tunnels, tunnel)
			s.reservedPorts[tunnel.PublicPort] = struct{}{}
			break
		}
	}
	s.mu.Unlock()
	if err := s.saveData(); err != nil {
		s.mu.Lock()
		s.removeTunnelConfigLocked(agentID, tunnel.ID)
		s.rollbackMappingsLocked(agent, []proto.Mapping{tunnel})
		s.mu.Unlock()
		return proto.Mapping{}, err
	}
	if err := agent.sendAndWaitAck(proto.Message{Type: proto.MsgTunnelAdd, Tunnel: &tunnel, TunnelID: tunnel.ID}); err != nil {
		_ = agent.send(proto.Message{Type: proto.MsgTunnelRemove, TunnelID: tunnel.ID})
		s.mu.Lock()
		s.removeTunnelConfigLocked(agentID, tunnel.ID)
		s.rollbackMappingsLocked(agent, []proto.Mapping{tunnel})
		s.mu.Unlock()
		if rollbackErr := s.saveData(); rollbackErr != nil {
			logging.Event("!", "rollback tunnel %s after notification failure: %v", tunnel.ID, rollbackErr)
		}
		s.disconnectAgent(agent, "tunnel acknowledgement failed")
		return proto.Mapping{}, fmt.Errorf("agent did not acknowledge tunnel: %w", err)
	}
	logging.Event("+", "tunnel %s added to %s: %s %d -> %s", tunnel.ID, agentID, tunnel.Network, tunnel.PublicPort, tunnel.TargetAddr)
	return tunnel, nil
}

func (s *relayServer) disconnectAgent(a *agent, reason string) {
	s.remove(a)
	_ = a.conn.CloseWithError(0, reason)
}

func newMappingID() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	value := binary.BigEndian.Uint64(b[:])
	if value == 0 {
		return 1
	}
	return value
}

func (s *relayServer) removeTunnelConfigLocked(agentID, id string) {
	for i := range s.cfg.Agents {
		if s.cfg.Agents[i].ID != agentID {
			continue
		}
		for j, tunnel := range s.cfg.Agents[i].Tunnels {
			if tunnel.ID == id {
				s.cfg.Agents[i].Tunnels = append(s.cfg.Agents[i].Tunnels[:j], s.cfg.Agents[i].Tunnels[j+1:]...)
				delete(s.reservedPorts, tunnel.PublicPort)
				return
			}
		}
	}
}

func validateTunnel(t proto.Mapping) error {
	if t.ID == "" || strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("tunnel ID and name are required")
	}
	if _, _, err := net.SplitHostPort(t.TargetAddr); err != nil {
		return fmt.Errorf("invalid target address: %w", err)
	}
	if t.Network != proto.NetworkTCP && t.Network != proto.NetworkUDP && t.Network != proto.NetworkBoth {
		return fmt.Errorf("network must be tcp, udp, or both")
	}
	return nil
}

func (s *relayServer) registerTunnel(agent *agent, tunnel *proto.Mapping) error {
	s.mu.Lock()
	portRange := s.cfg.PublicPortRange
	s.mu.Unlock()
	if portRange.Start == 0 || portRange.End == 0 {
		return fmt.Errorf("public_port_range is not configured")
	}
	count := int(portRange.End) - int(portRange.Start) + 1
	tried := make(map[uint16]struct{}, count)
	var lastErr error
	for len(tried) < count {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(count)))
		if err != nil {
			return fmt.Errorf("select random public port: %w", err)
		}
		port := uint16(int(portRange.Start) + int(n.Int64()))
		if _, seen := tried[port]; seen {
			continue
		}
		tried[port] = struct{}{}
		if s.portReservedByConfig(port) {
			continue
		}
		tunnel.PublicPort = port
		if err := s.register(agent, []proto.Mapping{*tunnel}); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr != nil {
		return fmt.Errorf("no available public port in %d-%d: %w", portRange.Start, portRange.End, lastErr)
	}
	return fmt.Errorf("no available public port in %d-%d", portRange.Start, portRange.End)
}

func (s *relayServer) portReservedByConfig(port uint16) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, reserved := s.reservedPorts[port]
	return reserved
}
func (s *relayServer) saveData() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored := tunnelData{Agents: make([]agentTunnelData, 0, len(s.cfg.Agents))}
	for _, agent := range s.cfg.Agents {
		if len(agent.Tunnels) == 0 {
			continue
		}
		stored.Agents = append(stored.Agents, agentTunnelData{ID: agent.ID, Tunnels: agent.Tunnels})
	}
	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}
	temp := s.dataPath + ".tmp"
	if err := os.WriteFile(temp, data, 0600); err != nil {
		return err
	}
	return os.Rename(temp, s.dataPath)
}
func newTunnelID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "tun-" + hex.EncodeToString(b)
}
