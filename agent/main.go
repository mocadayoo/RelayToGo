package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"RelayToGo/internal/logging"
	proto "RelayToGo/protocol"

	"github.com/quic-go/quic-go"
)

const agentUIAddr = "127.0.0.1:41002"

type udpSession struct {
	conn      *net.UDPConn
	port      uint16
	mappingID uint64
	flowID    uint64
	stats     *tunnelStats
}

type udpSessionKey struct {
	port              uint16
	mappingID, flowID uint64
}

type relayAgent struct {
	conn            *quic.Conn
	relayPublicAddr string
	tcp             map[uint16]proto.Mapping
	udp             map[uint16]proto.Mapping
	tunnels         map[string]proto.Mapping
	stats           map[string]*tunnelStats
	mu              sync.Mutex
	sessions        map[udpSessionKey]*udpSession
	pendingSessions map[udpSessionKey]struct{}
	retryAfter      map[udpSessionKey]time.Time
	control         *controlWriter
	pending         map[string]chan proto.Message
	requestSeq      atomic.Uint64
	lastPong        atomic.Int64
	maxDatagramSize atomic.Int64
}

func main() {
	logging.Configure()
	server := flag.String("server", "127.0.0.1:40000", "server QUIC address")
	flag.Parse()
	_, tlsConfig, publicKey, err := loadAgentTLS()
	if publicKey != "" {
		log.Printf("agent public key SHA-256: %s", publicKey)
	}
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	q, err := quic.DialAddr(ctx, *server, tlsConfig, &quic.Config{EnableDatagrams: true})
	if err != nil {
		log.Fatal(err)
	}

	defer q.CloseWithError(0, "shutdown")
	control, err := q.OpenStreamSync(ctx)
	if err != nil {
		log.Fatal(err)
	}

	enc, dec := json.NewEncoder(control), json.NewDecoder(control)
	if err := enc.Encode(proto.Message{Type: proto.MsgRegister}); err != nil {
		log.Fatal("send registration")
	}

	var reply proto.Message
	if err := dec.Decode(&reply); err != nil {
		log.Fatal("read assignment")
	}

	if reply.Type != proto.MsgRegistered {
		log.Fatalf("registration rejected: %s", reply.Reason)
	}

	a := &relayAgent{conn: q, relayPublicAddr: reply.RelayPublicAddr, tcp: map[uint16]proto.Mapping{}, udp: map[uint16]proto.Mapping{}, tunnels: map[string]proto.Mapping{}, stats: map[string]*tunnelStats{}, sessions: map[udpSessionKey]*udpSession{}, pendingSessions: map[udpSessionKey]struct{}{}, retryAfter: map[udpSessionKey]time.Time{}, pending: map[string]chan proto.Message{}}
	for _, t := range reply.Mappings {
		a.addTunnel(t)
	}
	a.lastPong.Store(time.Now().UnixNano())
	writer := &controlWriter{enc: enc, setWriteDeadline: control.SetWriteDeadline}
	a.control = writer
	go a.serveUI(agentUIAddr)
	go a.receiveUDP(ctx)
	go a.pruneUDPFailures(ctx)
	go a.controlLoop(ctx, dec, writer)
	go a.heartbeat(ctx, writer)
	log.Printf("attached: %d tunnel(s)", len(reply.Mappings))
	for {
		st, err := q.AcceptStream(ctx)
		if err != nil {
			return
		}

		go a.handleTCP(st)
	}
}
