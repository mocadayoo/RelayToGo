package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	proto "RelayToGo/protocol"
	temp "RelayToGo/temp"

	"github.com/quic-go/quic-go"
)

type config struct {
	QUICAddr   string        `json:"quic_addr"`
	PublicAddr string        `json:"public_addr"`
	Agents     []agentConfig `json:"agents"`
}

type agentConfig struct {
	ID      string          `json:"id"`
	Token   string          `json:"token"`
	Tunnels []proto.Mapping `json:"tunnels"`
}

type agent struct {
	id   string
	conn *quic.Conn
}

type tcpRelay struct {
	port  uint16
	agent *agent
	ln    net.Listener
}

type udpRelay struct {
	port       uint16
	agent      *agent
	conn       *net.UDPConn
	mu         sync.Mutex
	nextFlowID uint64
	flows      map[string]*udpFlow
	byID       map[uint64]*udpFlow
}

type udpFlow struct {
	id       uint64
	address  *net.UDPAddr
	lastSeen time.Time
}

type relayServer struct {
	mu  sync.Mutex
	cfg config
	tcp map[uint16]*tcpRelay
	udp map[uint16]*udpRelay
}

func main() {
	path := flag.String("config", "server/config.json", "server configuration")
	flag.Parse()
	cfg, err := loadConfig(*path)
	if err != nil {
		log.Fatal(err)
	}

	tlsConf, err := temp.GenerateTLSConfig()
	if err != nil {
		log.Fatal(err)
	}

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

	s := &relayServer{cfg: cfg, tcp: map[uint16]*tcpRelay{}, udp: map[uint16]*udpRelay{}}
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

	ids := map[string]bool{}
	tcp, udp := map[uint16]bool{}, map[uint16]bool{}
	for _, a := range c.Agents {
		if a.ID == "" || a.Token == "" || ids[a.ID] {
			return c, errors.New("agent id and token must be unique")
		}
		ids[a.ID] = true
		tunnelNames := map[string]bool{}
		for _, t := range a.Tunnels {
			if t.Name == "" || tunnelNames[t.Name] {
				return c, fmt.Errorf("agent %s tunnel names must be unique", a.ID)
			}

			tunnelNames[t.Name] = true

			if t.PublicPort == 0 {
				return c, errors.New("public_port is required")
			}
			if _, _, e := net.SplitHostPort(t.TargetAddr); e != nil {
				return c, e
			}
			switch t.Network {
			case proto.NetworkTCP:
				if tcp[t.PublicPort] {
					return c, fmt.Errorf("duplicate TCP port %d", t.PublicPort)
				}
				tcp[t.PublicPort] = true
			case proto.NetworkUDP:
				if udp[t.PublicPort] {
					return c, fmt.Errorf("duplicate UDP port %d", t.PublicPort)
				}
				udp[t.PublicPort] = true
			case proto.NetworkBoth:
				if tcp[t.PublicPort] || udp[t.PublicPort] {
					return c, fmt.Errorf("duplicate both port %d", t.PublicPort)
				}

				tcp[t.PublicPort], udp[t.PublicPort] = true, true
			default:
				return c, errors.New("network must be tcp, udp, or both")
			}
		}
	}
	return c, nil
}
