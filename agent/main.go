package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	proto "RelayToGo/protocol"

	"github.com/quic-go/quic-go"
)

type udpSession struct {
	conn   *net.UDPConn
	port   uint16
	flowID uint64
}

type relayAgent struct {
	conn            *quic.Conn
	relayPublicAddr string
	tcp             map[uint16]string
	udp             map[uint16]string
	tunnels         map[string]proto.Mapping
	stats           map[string]*tunnelStats
	mu              sync.Mutex
	sessions        map[string]*udpSession
	lastPong        atomic.Int64
}

func main() {
	server := flag.String("server", "127.0.0.1:40000", "server QUIC address")
	id := flag.String("id", "", "agent identifier")
	token := flag.String("token", "", "agent token")
	flag.Parse()
	if *id == "" || *token == "" {
		log.Fatal("-id and -token are required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	q, err := quic.DialAddr(ctx, *server, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"RelayToGo"},
	}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		log.Fatal(err)
	}

	defer q.CloseWithError(0, "shutdown")
	control, err := q.OpenStreamSync(ctx)
	if err != nil {
		log.Fatal(err)
	}

	enc, dec := json.NewEncoder(control), json.NewDecoder(control)
	if err := enc.Encode(proto.Message{Type: proto.MsgRegister, AgentID: *id, Token: *token}); err != nil {
		log.Fatal("send registration")
	}

	var reply proto.Message
	if err := dec.Decode(&reply); err != nil {
		log.Fatal("read assignment")
	}

	if reply.Type != proto.MsgRegistered {
		log.Fatalf("registration rejected: %s", reply.Reason)
	}

	a := &relayAgent{conn: q, relayPublicAddr: reply.RelayPublicAddr, tcp: map[uint16]string{}, udp: map[uint16]string{}, tunnels: map[string]proto.Mapping{}, stats: map[string]*tunnelStats{}, sessions: map[string]*udpSession{}}
	for _, t := range reply.Mappings {
		key := string(t.Network) + fmt.Sprintf(":%d", t.PublicPort)
		a.tunnels[key] = t
		a.stats[key] = &tunnelStats{}
		switch t.Network {
		case proto.NetworkTCP:
			a.tcp[t.PublicPort] = t.TargetAddr
		case proto.NetworkUDP:
			a.udp[t.PublicPort] = t.TargetAddr
		case proto.NetworkBoth:
			a.tcp[t.PublicPort] = t.TargetAddr
			a.udp[t.PublicPort] = t.TargetAddr
		}
	}
	a.lastPong.Store(time.Now().UnixNano())
	go a.runPanel(ctx)
	go a.receiveUDP(ctx)
	go a.heartbeat(ctx, control, enc, dec)
	log.Printf("attached: %d tunnel(s)", len(reply.Mappings))
	for {
		st, err := q.AcceptStream(ctx)
		if err != nil {
			return
		}

		go a.handleTCP(st)
	}
}
