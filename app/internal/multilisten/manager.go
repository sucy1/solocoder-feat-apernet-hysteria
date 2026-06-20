package multilisten

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/apernet/hysteria/app/v2/internal/firewall"
	"github.com/apernet/hysteria/core/v2/server"
	eUtils "github.com/apernet/hysteria/extras/v2/utils"
)

const (
	ProtocolUDP         = "udp"
	ProtocolFakeTCP     = "fake-tcp"
	ProtocolWeChatVideo = "wechat-video"
)

type ListenConfig struct {
	Addr     string `mapstructure:"addr"`
	Protocol string `mapstructure:"protocol"`
	ObfsType string `mapstructure:"obfsType"`
}

type PortManager interface {
	AddPort(cfg ListenConfig, hyConfig *server.Config) error
	RemovePort(addr string) error
	ListPorts() []ListenConfig
	Close() error
}

type portEntry struct {
	cfg     ListenConfig
	server  server.Server
	conn    net.PacketConn
	cleanup io.Closer
}

type portManagerImpl struct {
	mu     sync.RWMutex
	ports  map[string]*portEntry
	tlsCfg *server.Config
}

func NewPortManager() PortManager {
	return &portManagerImpl{
		ports: make(map[string]*portEntry),
	}
}

func (m *portManagerImpl) validateProtocol(protocol string) error {
	switch protocol {
	case "", ProtocolUDP, ProtocolFakeTCP, ProtocolWeChatVideo:
		return nil
	default:
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

func (m *portManagerImpl) checkPortConflict(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for existingAddr := range m.ports {
		existingHost, existingPort, err := net.SplitHostPort(existingAddr)
		if err != nil {
			continue
		}
		if port == existingPort && (host == existingHost || host == "" || existingHost == "" || host == "0.0.0.0" || existingHost == "0.0.0.0" || host == "::" || existingHost == "::") {
			return fmt.Errorf("port %s conflict: new addr %s conflicts with existing addr %s", port, addr, existingAddr)
		}
	}
	return nil
}

func (m *portManagerImpl) createPacketConn(cfg ListenConfig) (net.PacketConn, io.Closer, error) {
	protocol := cfg.Protocol
	if protocol == "" {
		protocol = ProtocolUDP
	}

	switch protocol {
	case ProtocolUDP:
		return m.createUDPConn(cfg.Addr)
	case ProtocolFakeTCP:
		return m.createFakeTCPConn(cfg.Addr)
	case ProtocolWeChatVideo:
		return m.createWeChatVideoConn(cfg.Addr)
	default:
		return nil, nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

func (m *portManagerImpl) createUDPConn(addr string) (net.PacketConn, io.Closer, error) {
	uAddr, portUnion, err := resolveListenAddr(addr)
	if err != nil {
		return nil, nil, err
	}
	conn, err := net.ListenUDP("udp", uAddr)
	if err != nil {
		return nil, nil, err
	}
	var cleanup io.Closer
	if len(portUnion) > 0 {
		cleanup, err = firewall.SetupUDPPortRedirect(uAddr, portUnion)
		if err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
	}
	return conn, cleanup, nil
}

func (m *portManagerImpl) createFakeTCPConn(addr string) (net.PacketConn, io.Closer, error) {
	return nil, nil, errors.New("fake-tcp protocol not implemented in this version")
}

func (m *portManagerImpl) createWeChatVideoConn(addr string) (net.PacketConn, io.Closer, error) {
	return nil, nil, errors.New("wechat-video protocol not implemented in this version")
}

func resolveListenAddr(listenAddr string) (*net.UDPAddr, eUtils.PortUnion, error) {
	host, portStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		uAddr, resolveErr := net.ResolveUDPAddr("udp", listenAddr)
		return uAddr, nil, resolveErr
	}
	if !containsAny(portStr, "-,") {
		uAddr, resolveErr := net.ResolveUDPAddr("udp", listenAddr)
		return uAddr, nil, resolveErr
	}
	portUnion := eUtils.ParsePortUnion(portStr)
	if portUnion == nil {
		return nil, nil, fmt.Errorf("%s is not a valid port number or range", portStr)
	}
	firstListenAddr := net.JoinHostPort(host, fmt.Sprintf("%d", portUnion[0].Start))
	uAddr, err := net.ResolveUDPAddr("udp", firstListenAddr)
	return uAddr, portUnion, err
}

func containsAny(s string, chars string) bool {
	for _, c := range chars {
		for _, sc := range s {
			if c == sc {
				return true
			}
		}
	}
	return false
}

func (m *portManagerImpl) AddPort(cfg ListenConfig, hyConfig *server.Config) error {
	if err := m.validateProtocol(cfg.Protocol); err != nil {
		return err
	}
	if cfg.Addr == "" {
		return errors.New("empty listen address")
	}
	if err := m.checkPortConflict(cfg.Addr); err != nil {
		return err
	}

	conn, cleanup, err := m.createPacketConn(cfg)
	if err != nil {
		return fmt.Errorf("failed to create packet connection: %w", err)
	}

	newConfig := *hyConfig
	newConfig.Conn = conn
	newConfig.Cleanup = cleanup

	s, err := server.NewServer(&newConfig)
	if err != nil {
		_ = conn.Close()
		if cleanup != nil {
			_ = cleanup.Close()
		}
		return fmt.Errorf("failed to create server: %w", err)
	}

	entry := &portEntry{
		cfg:     cfg,
		server:  s,
		conn:    conn,
		cleanup: cleanup,
	}

	m.mu.Lock()
	m.ports[cfg.Addr] = entry
	m.mu.Unlock()

	go func() {
		_ = s.Serve()
	}()

	return nil
}

func (m *portManagerImpl) RemovePort(addr string) error {
	m.mu.Lock()
	entry, ok := m.ports[addr]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("port not found: %s", addr)
	}
	delete(m.ports, addr)
	m.mu.Unlock()

	err := entry.server.Close()
	if entry.cleanup != nil {
		_ = entry.cleanup.Close()
	}
	return err
}

func (m *portManagerImpl) ListPorts() []ListenConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]ListenConfig, 0, len(m.ports))
	for _, entry := range m.ports {
		result = append(result, entry.cfg)
	}
	return result
}

func (m *portManagerImpl) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	for addr, entry := range m.ports {
		if err := entry.server.Close(); err != nil {
			errs = append(errs, fmt.Errorf("port %s: %w", addr, err))
		}
		if entry.cleanup != nil {
			if err := entry.cleanup.Close(); err != nil {
				errs = append(errs, fmt.Errorf("port %s cleanup: %w", addr, err))
			}
		}
	}
	m.ports = make(map[string]*portEntry)
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
