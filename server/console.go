package main

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"strings"
)

func (s *relayServer) readConsole(ctxDone <-chan struct{}) {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		select {
		case <-ctxDone:
			return
		default:
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "agents":
			s.printAgents()
		case "add":
			if len(fields) != 3 {
				log.Print("usage: add <agent-id> <public-key-sha256>")
				continue
			}
			s.addAgent(fields[1], fields[2])
		case "remove":
			if len(fields) != 2 {
				log.Print("usage: remove <agent-id>")
				continue
			}
			s.removeAgent(fields[1])
		case "help":
			log.Print("commands: agents | add <agent-id> <public-key-sha256> | remove <agent-id>")
		default:
			log.Print("unknown command; type help")
		}
	}
}

func (s *relayServer) printAgents() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, agent := range s.cfg.Agents {
		log.Printf("agent id=%s public_key_sha256=%s tunnels=%d", agent.ID, agent.PublicKeySHA256, len(agent.Tunnels))
	}
}

func (s *relayServer) addAgent(id, fingerprint string) {
	fingerprint = normalizeFingerprint(fingerprint)
	if _, err := agentKeyIndex([]agentConfig{{ID: id, PublicKeySHA256: fingerprint}}); err != nil {
		log.Print(err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, agent := range s.cfg.Agents {
		if agent.ID == id || normalizeFingerprint(agent.PublicKeySHA256) == fingerprint {
			log.Print("agent ID or public key is already registered")
			return
		}
	}
	s.cfg.Agents = append(s.cfg.Agents, agentConfig{ID: id, PublicKeySHA256: fingerprint})
	if err := s.saveAgentSecretsLocked(); err != nil {
		log.Printf("save agents: %v", err)
		return
	}
	log.Printf("agent %s added", id)
}

func (s *relayServer) removeAgent(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, agent := range s.cfg.Agents {
		if agent.ID != id {
			continue
		}
		if len(agent.Tunnels) != 0 || s.agents[id] != nil {
			log.Print("remove this agent's tunnels and disconnect it first")
			return
		}
		s.cfg.Agents = append(s.cfg.Agents[:i], s.cfg.Agents[i+1:]...)
		if err := s.saveAgentSecretsLocked(); err != nil {
			log.Printf("save agents: %v", err)
			return
		}
		log.Printf("agent %s removed", id)
		return
	}
	log.Print("agent not found")
}

func (s *relayServer) hasAgentKey(fingerprint string) bool {
	_, ok := s.agentByFingerprint(fingerprint)
	return ok
}

func (s *relayServer) agentByFingerprint(fingerprint string) (agentConfig, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, agent := range s.cfg.Agents {
		if normalizeFingerprint(agent.PublicKeySHA256) == normalizeFingerprint(fingerprint) {
			return agent, true
		}
	}
	return agentConfig{}, false
}

func (s *relayServer) saveAgentSecretsLocked() error {
	stored := agentSecrets{Agents: make([]agentConfig, 0, len(s.cfg.Agents))}
	for _, agent := range s.cfg.Agents {
		stored.Agents = append(stored.Agents, agentConfig{ID: agent.ID, PublicKeySHA256: agent.PublicKeySHA256})
	}
	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}
	temp := s.agentsPath + ".tmp"
	if err := os.WriteFile(temp, data, 0600); err != nil {
		return err
	}
	return os.Rename(temp, s.agentsPath)
}
