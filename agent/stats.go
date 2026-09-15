package main

import (
	"fmt"
	"io"
	"sync"

	proto "RelayToGo/protocol"
)

type tunnelStats struct {
	mu      sync.Mutex
	in      uint64
	out     uint64
	clients int
}

type countedReader struct {
	io.Reader
	count func(int)
}

func (r countedReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		r.count(n)
	}
	return n, err
}

func (s *tunnelStats) addIn(n int)     { s.mu.Lock(); s.in += uint64(n); s.mu.Unlock() }
func (s *tunnelStats) addOut(n int)    { s.mu.Lock(); s.out += uint64(n); s.mu.Unlock() }
func (s *tunnelStats) addClient(n int) { s.mu.Lock(); s.clients += n; s.mu.Unlock() }
func (s *tunnelStats) snapshot() (uint64, uint64, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.in, s.out, s.clients
}

func (a *relayAgent) statsFor(network proto.Network, port uint16) *tunnelStats {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.statsForLocked(network, port)
}

func (a *relayAgent) statsForLocked(network proto.Network, port uint16) *tunnelStats {
	if stats := a.stats[string(network)+fmt.Sprintf(":%d", port)]; stats != nil {
		return stats
	}
	return a.stats[string(proto.NetworkBoth)+fmt.Sprintf(":%d", port)]
}

func (a *relayAgent) tcpTargetAndStats(port uint16, mappingID uint64) (string, *tunnelStats) {
	a.mu.Lock()
	defer a.mu.Unlock()
	tunnel, ok := a.tcp[port]
	if !ok || tunnel.MappingID != mappingID {
		return "", nil
	}
	return tunnel.TargetAddr, a.statsForLocked(proto.NetworkTCP, port)
}

func (a *relayAgent) hasUDP(port uint16, mappingID uint64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	tunnel, ok := a.udp[port]
	return ok && tunnel.MappingID == mappingID
}
