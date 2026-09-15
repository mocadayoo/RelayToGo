package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"RelayToGo/internal/logging"
	proto "RelayToGo/protocol"

	"github.com/quic-go/quic-go"
)

type config struct {
	QUICAddr        string        `json:"quic_addr"`
	PublicAddr      string        `json:"public_addr"`
	PublicPortRange portRange     `json:"public_port_range"`
	Agents          []agentConfig `json:"agents"`
}

type portRange struct {
	Start uint16 `json:"start"`
	End   uint16 `json:"end"`
}

type agentConfig struct {
	ID              string          `json:"id"`
	PublicKeySHA256 string          `json:"public_key_sha256"`
	Tunnels         []proto.Mapping `json:"-"`
}

type agentSecrets struct {
	Agents []agentConfig `json:"agents"`
}

type tunnelData struct {
	Agents []agentTunnelData `json:"agents"`
}

type agentTunnelData struct {
	ID      string          `json:"id"`
	Tunnels []proto.Mapping `json:"tunnels"`
}

type agent struct {
	id         string
	conn       *quic.Conn
	outbound   chan proto.Message
	done       chan struct{}
	acks       map[string]chan proto.Message
	mu         sync.Mutex
	operations chan proto.Message
	closeOnce  sync.Once
	maxDatagramSize atomic.Int64
}

type tcpRelay struct {
	tunnel proto.Mapping
	agent  *agent
	ln     net.Listener
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

type udpRelay struct {
	tunnel     proto.Mapping
	agent      *agent
	conn       *net.UDPConn
	mu         sync.Mutex
	nextFlowID uint64
	flows      map[netip.AddrPort]*udpFlow
	byID       map[uint64]*udpFlow
	done       chan struct{}
	closeOnce  sync.Once
	dropped    atomic.Uint64
}

type udpFlow struct {
	id       uint64
	address  netip.AddrPort
	lastSeen time.Time
}

type portReservation struct {
	tcp int
	udp int
}

type relayServer struct {
	mu            sync.Mutex
	cfg           config
	agentsPath    string
	dataPath      string
	agents        map[string]*agent
	tcp           map[uint16]*tcpRelay
	udp           map[uint16]*udpRelay
	udpSnapshot   atomic.Value
	// reservedPorts tracks persisted mappings by transport protocol. TCP and UDP
	// intentionally share a numeric port when their respective reservations allow it.
	reservedPorts map[uint16]portReservation
}

func main() {
	logging.Configure()
	path := flag.String("config", "server/config.json", "server configuration")
	flag.Parse()
	cfg, err := loadConfig(*path)
	if err != nil {
		log.Fatal(err)
	}
	secretDir := filepath.Join(filepath.Dir(*path), "secret")
	if err := loadAgentSecrets(filepath.Join(secretDir, "agents.json"), &cfg); err != nil {
		log.Fatal(err)
	}
	dataPath := filepath.Join(secretDir, "data.json")
	if err := loadTunnelData(dataPath, &cfg); err != nil {
		log.Fatal(err)
	}
	s := &relayServer{cfg: cfg, agentsPath: filepath.Join(secretDir, "agents.json"), dataPath: dataPath, agents: map[string]*agent{}, tcp: map[uint16]*tcpRelay{}, udp: map[uint16]*udpRelay{}, reservedPorts: map[uint16]portReservation{}}
	for _, agent := range cfg.Agents {
		for _, tunnel := range agent.Tunnels {
			s.reserveTunnelLocked(tunnel)
		}
	}
	s.udpSnapshot.Store(map[uint16]*udpRelay{})
	tlsConf, serverFingerprint, err := loadOrCreateServerTLS(secretDir, s.hasAgentKey)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("server public key SHA-256: %s", serverFingerprint)

	addr, err := net.ResolveUDPAddr("udp", cfg.QUICAddr)
	if err != nil {
		log.Fatal(err)
	}

	sock, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
	}

	defer sock.Close()
	ln, err := quic.Listen(sock, tlsConf, &quic.Config{EnableDatagrams: true})
	if err != nil {
		log.Fatal(err)
	}

	defer ln.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go s.readConsole(ctx.Done())
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}

			continue
		}
		go s.handleAgent(ctx, conn)
	}
}

func loadConfig(path string) (config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return config{}, err
	}

	var c config
	if err = json.Unmarshal(data, &c); err != nil {
		return c, err
	}

	if c.QUICAddr == "" {
		return c, errors.New("quic_addr is required")
	}
	if c.PublicAddr == "" {
		return c, errors.New("public_addr is required")
	}
	if (c.PublicPortRange.Start == 0) != (c.PublicPortRange.End == 0) ||
		(c.PublicPortRange.Start != 0 && c.PublicPortRange.Start > c.PublicPortRange.End) {
		return c, errors.New("public_port_range must contain an ordered start and end")
	}

	return c, nil
}

func loadAgentSecrets(path string, c *config) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		data, err = json.MarshalIndent(agentSecrets{Agents: []agentConfig{}}, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			return err
		}
		log.Printf("created %s; type add <agent-id> <public-key-sha256> in this terminal", path)
		c.Agents = nil
		return nil
	}
	if err != nil {
		return err
	}
	var secrets agentSecrets
	if err := json.Unmarshal(data, &secrets); err != nil {
		return err
	}
	c.Agents = secrets.Agents
	return validateAgentSecrets(c.Agents)
}

func validateAgentSecrets(agents []agentConfig) error {
	ids := map[string]bool{}
	for _, a := range agents {
		if a.ID == "" || ids[a.ID] {
			return errors.New("agent IDs must be unique")
		}
		ids[a.ID] = true
	}
	return nil
}

func loadTunnelData(path string, c *config) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		data, err := json.MarshalIndent(tunnelData{Agents: []agentTunnelData{}}, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			return err
		}
		log.Printf("created %s", path)
		return nil
	}
	if err != nil {
		return err
	}
	var stored tunnelData
	if err := json.Unmarshal(data, &stored); err != nil {
		return err
	}
	indexes := make(map[string]int, len(c.Agents))
	for i, agent := range c.Agents {
		indexes[agent.ID] = i
	}
	seen := map[string]bool{}
	for _, agent := range stored.Agents {
		index, ok := indexes[agent.ID]
		if !ok || seen[agent.ID] {
			return fmt.Errorf("data contains an unknown or duplicate agent %q", agent.ID)
		}
		seen[agent.ID] = true
		c.Agents[index].Tunnels = agent.Tunnels
	}
	return validateConfiguredTunnels(*c)
}

func validateConfiguredTunnels(c config) error {
	tcp, udp := map[uint16]bool{}, map[uint16]bool{}
	for _, a := range c.Agents {
		tunnelNames := map[string]bool{}
		tunnelIDs := map[string]bool{}
		for _, t := range a.Tunnels {
			if t.ID == "" || tunnelIDs[t.ID] {
				return fmt.Errorf("agent %s tunnel IDs must be unique", a.ID)
			}

			tunnelIDs[t.ID] = true

			if t.Name == "" || tunnelNames[t.Name] {
				return fmt.Errorf("agent %s tunnel names must be unique", a.ID)
			}

			tunnelNames[t.Name] = true

			if t.PublicPort == 0 {
				return errors.New("public_port is required")
			}
			if _, _, e := net.SplitHostPort(t.TargetAddr); e != nil {
				return e
			}
			switch t.Network {
			case proto.NetworkTCP:
				if tcp[t.PublicPort] {
					return fmt.Errorf("duplicate TCP port %d", t.PublicPort)
				}
				tcp[t.PublicPort] = true
			case proto.NetworkUDP:
				if udp[t.PublicPort] {
					return fmt.Errorf("duplicate UDP port %d", t.PublicPort)
				}
				udp[t.PublicPort] = true
			case proto.NetworkBoth:
				if tcp[t.PublicPort] || udp[t.PublicPort] {
					return fmt.Errorf("duplicate both port %d", t.PublicPort)
				}

				tcp[t.PublicPort], udp[t.PublicPort] = true, true
			default:
				return errors.New("network must be tcp, udp, or both")
			}
		}
	}
	return nil
}
