package outbounds

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	StrategyRandom        = "random"
	StrategyRoundRobin    = "round-robin"
	StrategyLowestLatency = "lowest-latency"

	defaultLatencyProbeInterval = 30 * time.Second
	defaultLatencyProbeTimeout  = 5 * time.Second
)

type OutboundStrategy struct {
	Strategy         string
	ProbeInterval    time.Duration
	ProbeTimeout     time.Duration
	ProbeAddr        string
}

type strategyOutbound struct {
	outbounds []OutboundEntry
	strategy  string
	probeAddr string
	probeTimeout time.Duration

	mu        sync.RWMutex
	latencies map[string]time.Duration
	rrIndex   uint32

	ctx    context.Context
	cancel context.CancelFunc
}

func NewStrategyOutbound(outbounds []OutboundEntry, cfg OutboundStrategy) (PluggableOutbound, error) {
	if len(outbounds) == 0 {
		return nil, errors.New("no outbounds provided")
	}

	strategy := cfg.Strategy
	if strategy == "" {
		strategy = StrategyRandom
	}

	probeAddr := cfg.ProbeAddr
	if probeAddr == "" {
		probeAddr = "8.8.8.8:53"
	}

	probeTimeout := cfg.ProbeTimeout
	if probeTimeout == 0 {
		probeTimeout = defaultLatencyProbeTimeout
	}

	probeInterval := cfg.ProbeInterval
	if probeInterval == 0 {
		probeInterval = defaultLatencyProbeInterval
	}

	ctx, cancel := context.WithCancel(context.Background())

	so := &strategyOutbound{
		outbounds:    outbounds,
		strategy:     strategy,
		probeAddr:    probeAddr,
		probeTimeout: probeTimeout,
		latencies:    make(map[string]time.Duration),
		ctx:          ctx,
		cancel:       cancel,
	}

	for _, ob := range outbounds {
		so.latencies[ob.Name] = time.Duration(0)
	}

	if strategy == StrategyLowestLatency {
		go so.probeLoop(probeInterval)
	}

	return so, nil
}

func (s *strategyOutbound) probeLoop(interval time.Duration) {
	s.probeAll()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.probeAll()
		}
	}
}

func (s *strategyOutbound) probeAll() {
	var wg sync.WaitGroup
	for _, ob := range s.outbounds {
		wg.Add(1)
		go func(name string, outbound PluggableOutbound) {
			defer wg.Done()
			latency := s.probeOne(outbound)
			s.mu.Lock()
			s.latencies[name] = latency
			s.mu.Unlock()
		}(ob.Name, ob.Outbound)
	}
	wg.Wait()
}

func (s *strategyOutbound) probeOne(outbound PluggableOutbound) time.Duration {
	start := time.Now()
	ctx, cancel := context.WithTimeout(s.ctx, s.probeTimeout)
	defer cancel()

	conn, err := outbound.TCP(&AddrEx{
		Host: "8.8.8.8",
		Port: 53,
	})
	if err != nil {
		return time.Hour
	}
	defer conn.Close()

	_ = ctx
	return time.Since(start)
}

func (s *strategyOutbound) selectOutbound() (PluggableOutbound, string) {
	switch s.strategy {
	case StrategyRandom:
		return s.selectRandom()
	case StrategyRoundRobin:
		return s.selectRoundRobin()
	case StrategyLowestLatency:
		return s.selectLowestLatency()
	default:
		return s.selectRandom()
	}
}

func (s *strategyOutbound) selectRandom() (PluggableOutbound, string) {
	idx := rand.Intn(len(s.outbounds))
	ob := s.outbounds[idx]
	return ob.Outbound, ob.Name
}

func (s *strategyOutbound) selectRoundRobin() (PluggableOutbound, string) {
	idx := atomic.AddUint32(&s.rrIndex, 1) % uint32(len(s.outbounds))
	ob := s.outbounds[idx]
	return ob.Outbound, ob.Name
}

func (s *strategyOutbound) selectLowestLatency() (PluggableOutbound, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var bestName string
	var bestLatency time.Duration = time.Hour

	for _, ob := range s.outbounds {
		latency := s.latencies[ob.Name]
		if latency < bestLatency {
			bestLatency = latency
			bestName = ob.Name
		}
	}

	if bestName == "" {
		ob := s.outbounds[0]
		return ob.Outbound, ob.Name
	}

	for _, ob := range s.outbounds {
		if ob.Name == bestName {
			return ob.Outbound, ob.Name
		}
	}

	ob := s.outbounds[0]
	return ob.Outbound, ob.Name
}

func (s *strategyOutbound) TCP(reqAddr *AddrEx) (net.Conn, error) {
	ob, name := s.selectOutbound()
	conn, err := ob.TCP(reqAddr)
	if err != nil {
		return nil, fmt.Errorf("outbound %s: %w", name, err)
	}
	return conn, nil
}

func (s *strategyOutbound) UDP(reqAddr *AddrEx) (UDPConn, error) {
	ob, name := s.selectOutbound()
	conn, err := ob.UDP(reqAddr)
	if err != nil {
		return nil, fmt.Errorf("outbound %s: %w", name, err)
	}
	return conn, nil
}

func (s *strategyOutbound) CheckUDP(reqAddr *AddrEx) error {
	ob, _ := s.selectOutbound()
	return ob.CheckUDP(reqAddr)
}

func (s *strategyOutbound) Close() error {
	s.cancel()
	return nil
}
