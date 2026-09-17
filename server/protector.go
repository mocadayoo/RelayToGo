package main

import (
	"context"
	"net"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	proto "RelayToGo/protocol"
)

const (
	protectorTick          = 100 * time.Millisecond
	protectorSampleEvery   = 10
	protectorDefaultBudget = int64(4 << 30)
	protector32BitBudget   = int64(768 << 20)
)

type trafficDirection uint8

const (
	trafficToAgent trafficDirection = iota
	trafficFromAgent
)

type protector struct {
	toAgent           byteBucket
	fromAgent         byteBucket
	toAgentPackets    byteBucket
	fromAgentPackets  byteBucket
	handshakes        byteBucket
	handshakePressure atomic.Bool

	tcpActive     atomic.Int64
	udpActive     atomic.Int64
	tcpLimit      atomic.Int64
	udpLimit      atomic.Int64
	byteRate      atomic.Int64
	packetRate    atomic.Int64
	handshakeRate atomic.Int64

	minTCP           int64
	maxTCP           int64
	minUDP           int64
	maxUDP           int64
	minRate          int64
	maxRate          int64
	minPacketRate    int64
	maxPacketRate    int64
	minHandshakeRate int64
	maxHandshakeRate int64
	budget           int64

	mu      sync.Mutex
	tunnels map[*tunnelProtector]struct{}
}

type tunnelProtector struct {
	owner            *protector
	toAgent          byteBucket
	fromAgent        byteBucket
	toAgentPackets   byteBucket
	fromAgentPackets byteBucket
	tcpLogs          byteBucket
	tcp              bool
	udp              bool

	tcpActive atomic.Int64
	udpActive atomic.Int64
	tcpLimit  atomic.Int64
	udpLimit  atomic.Int64
	refs      atomic.Int32
}

type byteBucket struct {
	tokens   atomic.Int64
	burst    atomic.Int64
	rate     atomic.Int64
	minBurst int64
}

func newProtector() *protector {
	cores := int64(runtime.GOMAXPROCS(0))
	if cores < 1 {
		cores = 1
	}
	budget := debug.SetMemoryLimit(-1)
	if budget <= 0 || budget > protectorDefaultBudget {
		budget = protectorDefaultBudget
	}
	if ^uint(0)>>32 == 0 && budget > protector32BitBudget {
		budget = protector32BitBudget
	}

	tcpBase := max(int64(64), budget/8/(256<<10))
	udpBase := max(int64(512), budget/8/(64<<10))

	p := &protector{
		minTCP:           max(32, tcpBase/4),
		maxTCP:           tcpBase * 2,
		minUDP:           max(256, udpBase/4),
		maxUDP:           udpBase * 2,
		minRate:          8 << 20,
		maxRate:          512 << 20,
		minPacketRate:    4 << 10,
		maxPacketRate:    64 << 10,
		minHandshakeRate: 16 * cores,
		maxHandshakeRate: 256 * cores,
		budget:           budget,
		tunnels:          make(map[*tunnelProtector]struct{}),
	}
	p.tcpLimit.Store(tcpBase)
	p.udpLimit.Store(udpBase)
	if ^uint(0)>>32 == 0 {
		p.maxRate = 128 << 20
		p.maxPacketRate = 32 << 10
	}
	p.byteRate.Store(64 << 20)
	p.packetRate.Store(16 << 10)
	p.handshakeRate.Store(64 * cores)
	p.toAgent.init(p.byteRate.Load(), 64<<10)
	p.fromAgent.init(p.byteRate.Load(), 64<<10)
	p.toAgentPackets.init(p.packetRate.Load(), 64)
	p.fromAgentPackets.init(p.packetRate.Load(), 64)
	p.handshakes.init(p.handshakeRate.Load(), 8)
	return p
}

func (p *protector) run(ctx context.Context) {
	ticker := time.NewTicker(protectorTick)
	defer ticker.Stop()
	last := time.Now()
	lagged := false
	for ticks := 1; ; ticks++ {
		select {
		case <-ticker.C:
			now := time.Now()
			lagged = lagged || now.Sub(last) > 2*protectorTick
			last = now
			p.refill()
			if ticks%protectorSampleEvery == 0 {
				p.adjust(lagged)
				lagged = false
			}
		case <-ctx.Done():
			return
		}
	}
}

func (p *protector) newTunnel(network proto.Network) *tunnelProtector {
	rate := p.byteRate.Load()
	t := &tunnelProtector{
		owner: p,
		tcp:   network == proto.NetworkTCP || network == proto.NetworkBoth,
		udp:   network == proto.NetworkUDP || network == proto.NetworkBoth,
	}
	t.toAgent.init(rate, 64<<10)
	t.fromAgent.init(rate, 64<<10)
	t.toAgentPackets.init(p.packetRate.Load(), 64)
	t.fromAgentPackets.init(p.packetRate.Load(), 64)
	t.tcpLogs.init(10, 10)
	refs := int32(1)
	if network == proto.NetworkBoth {
		refs = 2
	}
	t.refs.Store(refs)

	p.mu.Lock()
	p.tunnels[t] = struct{}{}
	p.rebalanceTunnelsLocked()
	p.mu.Unlock()
	return t
}

func (t *tunnelProtector) releaseRelay() {
	if t.refs.Add(-1) != 0 {
		return
	}
	t.owner.mu.Lock()
	delete(t.owner.tunnels, t)
	t.owner.rebalanceTunnelsLocked()
	t.owner.mu.Unlock()
}

func (p *protector) refill() {
	p.toAgent.refill()
	p.fromAgent.refill()
	p.toAgentPackets.refill()
	p.fromAgentPackets.refill()
	p.handshakes.refill()
	p.mu.Lock()
	for tunnel := range p.tunnels {
		tunnel.toAgent.refill()
		tunnel.fromAgent.refill()
		tunnel.toAgentPackets.refill()
		tunnel.fromAgentPackets.refill()
		tunnel.tcpLogs.refill()
	}
	p.mu.Unlock()
}

func (p *protector) adjust(schedulerLag bool) {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	active := p.tcpActive.Load() + p.udpActive.Load()
	busyMemory := int64(stats.Sys) > p.budget*4/5
	busyRoutines := int64(runtime.NumGoroutine()) > 4*active+1024
	admissionSaturated := p.tcpActive.Load()*10 >= p.tcpLimit.Load()*9 ||
		p.udpActive.Load()*10 >= p.udpLimit.Load()*9
	handshakePressure := p.handshakePressure.Swap(false)
	resourcePressure := busyMemory || busyRoutines || schedulerLag

	if resourcePressure {
		p.tcpLimit.Store(decrease(p.tcpLimit.Load(), p.minTCP))
		p.udpLimit.Store(decrease(p.udpLimit.Load(), p.minUDP))
		p.byteRate.Store(decrease(p.byteRate.Load(), p.minRate))
		p.packetRate.Store(decrease(p.packetRate.Load(), p.minPacketRate))
	} else if !admissionSaturated {
		p.tcpLimit.Store(increase(p.tcpLimit.Load(), p.maxTCP))
		p.udpLimit.Store(increase(p.udpLimit.Load(), p.maxUDP))
		p.byteRate.Store(increase(p.byteRate.Load(), p.maxRate))
		p.packetRate.Store(increase(p.packetRate.Load(), p.maxPacketRate))
	}

	if resourcePressure || handshakePressure {
		p.handshakeRate.Store(decrease(p.handshakeRate.Load(), p.minHandshakeRate))
	} else {
		p.handshakeRate.Store(increase(p.handshakeRate.Load(), p.maxHandshakeRate))
	}

	rate := p.byteRate.Load()
	p.toAgent.setRate(rate)
	p.fromAgent.setRate(rate)
	p.toAgentPackets.setRate(p.packetRate.Load())
	p.fromAgentPackets.setRate(p.packetRate.Load())
	p.handshakes.setRate(p.handshakeRate.Load())
	p.mu.Lock()
	p.rebalanceTunnelsLocked()
	p.mu.Unlock()
}

func (p *protector) verifySourceAddress(_ net.Addr) bool {
	if p.handshakes.take(1) {
		return false
	}
	p.handshakePressure.Store(true)
	return true
}

func (p *protector) rebalanceTunnelsLocked() {
	count := int64(len(p.tunnels))
	if count == 0 {
		return
	}
	var tcpCount, udpCount int64
	for tunnel := range p.tunnels {
		if tunnel.tcp {
			tcpCount++
		}
		if tunnel.udp {
			udpCount++
		}
	}

	tcpShare := max(1, 2*p.tcpLimit.Load()/max(1, tcpCount))
	udpShare := max(1, 2*p.udpLimit.Load()/max(1, udpCount))
	rateShare := max(int64(64<<10), 2*p.byteRate.Load()/count)
	packetShare := max(int64(64), 2*p.packetRate.Load()/max(1, udpCount))
	for tunnel := range p.tunnels {
		tunnel.tcpLimit.Store(tcpShare)
		tunnel.udpLimit.Store(udpShare)
		tunnel.toAgent.setRate(rateShare)
		tunnel.fromAgent.setRate(rateShare)
		tunnel.toAgentPackets.setRate(packetShare)
		tunnel.fromAgentPackets.setRate(packetShare)
	}
}

func decrease(current, floor int64) int64 {
	next := current * 3 / 4
	if next < floor {
		return floor
	}
	return next
}

func increase(current, ceiling int64) int64 {
	next := current + max(1, current/20)
	if next > ceiling {
		return ceiling
	}
	return next
}

func acquire(counter *atomic.Int64, limit int64) bool {
	for {
		current := counter.Load()
		if current >= limit {
			return false
		}
		if counter.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func (t *tunnelProtector) acquireTCP() bool {
	p := t.owner
	if !acquire(&p.tcpActive, p.tcpLimit.Load()) {
		return false
	}
	if !acquire(&t.tcpActive, t.tcpLimit.Load()) {
		p.tcpActive.Add(-1)
		return false
	}
	return true
}

func (t *tunnelProtector) releaseTCP() {
	t.tcpActive.Add(-1)
	t.owner.tcpActive.Add(-1)
}

func (t *tunnelProtector) acquireUDP() bool {
	p := t.owner
	if !acquire(&p.udpActive, p.udpLimit.Load()) {
		return false
	}
	if !acquire(&t.udpActive, t.udpLimit.Load()) {
		p.udpActive.Add(-1)
		return false
	}
	return true
}

func (t *tunnelProtector) releaseUDP() {
	t.udpActive.Add(-1)
	t.owner.udpActive.Add(-1)
}

func (t *tunnelProtector) udpIdleTimeout() time.Duration {
	active := t.udpActive.Load()
	limit := t.udpLimit.Load()
	globalActive := t.owner.udpActive.Load()
	globalLimit := t.owner.udpLimit.Load()
	if active*10 >= limit*9 || globalActive*10 >= globalLimit*9 {
		return 15 * time.Second
	}
	if active*4 >= limit*3 || globalActive*4 >= globalLimit*3 {
		return 30 * time.Second
	}
	if active*2 >= limit || globalActive*2 >= globalLimit {
		return time.Minute
	}
	return 2 * time.Minute
}

func (t *tunnelProtector) tcpIdleTimeout() time.Duration {
	active := t.tcpActive.Load()
	limit := t.tcpLimit.Load()
	globalActive := t.owner.tcpActive.Load()
	globalLimit := t.owner.tcpLimit.Load()
	if active*10 >= limit*9 || globalActive*10 >= globalLimit*9 {
		return 30 * time.Second
	}
	if active*4 >= limit*3 || globalActive*4 >= globalLimit*3 {
		return 2 * time.Minute
	}
	if active*2 >= limit || globalActive*2 >= globalLimit {
		return 10 * time.Minute
	}
	return 30 * time.Minute
}

func (t *tunnelProtector) allowTCPLog() bool {
	return t.tcpLogs.take(1)
}

func (t *tunnelProtector) waitBytes(done <-chan struct{}, direction trafficDirection, size int) bool {
	tunnelBucket, globalBucket := t.buckets(direction)
	if !tunnelBucket.wait(done, int64(size)) {
		return false
	}
	if !globalBucket.wait(done, int64(size)) {
		tunnelBucket.refund(int64(size))
		return false
	}
	return true
}

func (t *tunnelProtector) allowDatagram(direction trafficDirection, size int) bool {
	tunnelBucket, globalBucket := t.buckets(direction)
	tunnelPackets, globalPackets := t.packetBuckets(direction)
	amount := int64(size)
	if !tunnelPackets.take(1) {
		return false
	}
	if !globalPackets.take(1) {
		tunnelPackets.refund(1)
		return false
	}
	if !tunnelBucket.take(amount) {
		tunnelPackets.refund(1)
		globalPackets.refund(1)
		return false
	}
	if !globalBucket.take(amount) {
		tunnelBucket.refund(amount)
		tunnelPackets.refund(1)
		globalPackets.refund(1)
		return false
	}
	return true
}

func (t *tunnelProtector) packetBuckets(direction trafficDirection) (*byteBucket, *byteBucket) {
	if direction == trafficFromAgent {
		return &t.fromAgentPackets, &t.owner.fromAgentPackets
	}
	return &t.toAgentPackets, &t.owner.toAgentPackets
}

func (t *tunnelProtector) buckets(direction trafficDirection) (*byteBucket, *byteBucket) {
	if direction == trafficFromAgent {
		return &t.fromAgent, &t.owner.fromAgent
	}
	return &t.toAgent, &t.owner.toAgent
}

func (b *byteBucket) init(rate, minBurst int64) {
	b.minBurst = minBurst
	b.setRate(rate)
	b.tokens.Store(b.burst.Load())
}

func (b *byteBucket) setRate(rate int64) {
	if rate < 1 {
		rate = 1
	}
	burst := max(b.minBurst, rate/4)
	b.rate.Store(rate)
	b.burst.Store(burst)
	for {
		current := b.tokens.Load()
		if current <= burst || b.tokens.CompareAndSwap(current, burst) {
			break
		}
	}
}

func (b *byteBucket) refill() {
	amount := b.rate.Load() / int64(time.Second/protectorTick)
	burst := b.burst.Load()
	for {
		current := b.tokens.Load()
		next := min(burst, current+amount)
		if b.tokens.CompareAndSwap(current, next) {
			break
		}
	}
}

func (b *byteBucket) take(amount int64) bool {
	if amount <= 0 {
		return true
	}
	for {
		current := b.tokens.Load()
		if current < amount {
			return false
		}
		if b.tokens.CompareAndSwap(current, current-amount) {
			return true
		}
	}
}

func (b *byteBucket) refund(amount int64) {
	burst := b.burst.Load()
	for {
		current := b.tokens.Load()
		next := min(burst, current+amount)
		if b.tokens.CompareAndSwap(current, next) {
			return
		}
	}
}

func (b *byteBucket) wait(done <-chan struct{}, amount int64) bool {
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	var taken int64
	for amount > 0 {
		chunk := min(amount, b.burst.Load())
		if b.take(chunk) {
			amount -= chunk
			taken += chunk
			continue
		}
		if timer == nil {
			timer = time.NewTimer(protectorTick)
		} else {
			timer.Reset(protectorTick)
		}
		select {
		case <-timer.C:
		case <-done:
			b.refund(taken)
			return false
		}
	}
	return true
}
