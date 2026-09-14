package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"

	proto "RelayToGo/protocol"
)

type tunnelRequest struct {
	AgentID string `json:"agent_id"`
	proto.Mapping
}

func (s *relayServer) serveAPI(address string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tunnels", s.tunnelsAPI)
	mux.HandleFunc("/api/tunnels/", s.tunnelAPI)
	_ = http.ListenAndServe(address, s.apiAuth(mux))
}
func (s *relayServer) tunnelAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", 405)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/tunnels/")
	if deleted, err := s.deleteTunnel(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if deleted {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.NotFound(w, r)
}

func (s *relayServer) apiAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.APIToken != "" && r.Header.Get("Authorization") != "Bearer "+s.cfg.APIToken {
			http.Error(w, "unauthorized", 401)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *relayServer) tunnelsAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		defer s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(s.cfg.Agents)
	case http.MethodPost:
		var request tunnelRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		tunnel, err := s.createTunnel(request.AgentID, request.Mapping)
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		request.Mapping = tunnel
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(request)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (s *relayServer) createTunnel(agentID string, tunnel proto.Mapping) (proto.Mapping, error) {
	if tunnel.ID == "" {
		tunnel.ID = newTunnelID()
	}
	tunnel.PublicPort = 0
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
	if !s.notifyTunnelAdd(agentID, tunnel) {
		return proto.Mapping{}, fmt.Errorf("agent notification failed")
	}
	s.mu.Lock()
	for i := range s.cfg.Agents {
		if s.cfg.Agents[i].ID == agentID {
			s.cfg.Agents[i].Tunnels = append(s.cfg.Agents[i].Tunnels, tunnel)
			break
		}
	}
	s.mu.Unlock()
	if err := s.saveData(); err != nil {
		return proto.Mapping{}, err
	}
	return tunnel, nil
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
	for _, agent := range s.cfg.Agents {
		for _, tunnel := range agent.Tunnels {
			if tunnel.PublicPort == port {
				return true
			}
		}
	}
	return false
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
