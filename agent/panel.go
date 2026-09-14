package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	proto "RelayToGo/protocol"
)

type tunnelStats struct {
	mu      sync.Mutex
	in      uint64
	out     uint64
	clients int
}

func (s *tunnelStats) addIn(n int)     { s.mu.Lock(); s.in += uint64(n); s.mu.Unlock() }
func (s *tunnelStats) addOut(n int)    { s.mu.Lock(); s.out += uint64(n); s.mu.Unlock() }
func (s *tunnelStats) addClient(n int) { s.mu.Lock(); s.clients += n; s.mu.Unlock() }
func (s *tunnelStats) snapshot() (uint64, uint64, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.in, s.out, s.clients
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

func (a *relayAgent) statsFor(network proto.Network, port uint16) *tunnelStats {
	if stats := a.stats[string(network)+fmt.Sprintf(":%d", port)]; stats != nil { return stats }

	return a.stats[string(proto.NetworkBoth)+fmt.Sprintf(":%d", port)]
}

func (a *relayAgent) runPanel(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		a.printPanel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (a *relayAgent) printPanel() {
	keys := make([]string, 0, len(a.tunnels))
	for key := range a.tunnels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	fmt.Fprint(os.Stdout, "\033[H\033[2JRelayToGo agent\n\nTUNNELS\n")
	for _, key := range keys {
		t := a.tunnels[key]
		in, out, clients := a.statsFor(t.Network, t.PublicPort).snapshot()
		fmt.Fprintf(os.Stdout, "[%s] %s  %s <-> %s:%d\n", t.Name, t.Network, t.TargetAddr, a.relayPublicAddr, t.PublicPort)
		fmt.Fprintf(os.Stdout, "  IN: %-8s OUT: %-8s Clients: %d\n", formatBytes(in), formatBytes(out), clients)
	}
}

func formatBytes(n uint64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	value := float64(n)
	i := 0
	for value >= 1024 && i < len(units)-1 {
		value /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d %s", n, units[i])
	}
	return fmt.Sprintf("%.1f %s", value, units[i])
}
