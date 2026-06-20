package connlog

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const (
	ConnTypeTCP = "tcp"
	ConnTypeUDP = "udp"
)

type ConnLogEntry struct {
	Time      string `json:"time"`
	Type      string `json:"type"`
	SourceIP  string `json:"source_ip"`
	Target    string `json:"target"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxBytes   uint64 `json:"rx_bytes"`
	DurationMs int64 `json:"duration_ms"`
	UserID    string `json:"user_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

type JSONConnLogger interface {
	LogConnect(typ string, addr net.Addr, id string, target string)
	LogDisconnect(addr net.Addr, id string, target string, tx, rx uint64, duration time.Duration, err error)
	LogTCPRequest(addr net.Addr, id, reqAddr string)
	LogTCPError(addr net.Addr, id, reqAddr string, err error)
	LogUDPRequest(addr net.Addr, id string, sessionID uint32, reqAddr string)
	LogUDPError(addr net.Addr, id string, sessionID uint32, err error)
}

type jsonConnLoggerImpl struct {
	writer io.Writer
	mu     sync.Mutex
}

func NewJSONConnLogger(output string) (JSONConnLogger, error) {
	var writer io.Writer
	if output == "" || output == "stdout" {
		writer = os.Stdout
	} else if output == "stderr" {
		writer = os.Stderr
	} else {
		f, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		writer = f
	}
	return &jsonConnLoggerImpl{
		writer: writer,
	}, nil
}

func (l *jsonConnLoggerImpl) writeEntry(entry ConnLogEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry.Time = time.Now().Format(time.RFC3339Nano)
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_, _ = l.writer.Write(data)
	_, _ = l.writer.Write([]byte("\n"))
}

func (l *jsonConnLoggerImpl) LogConnect(typ string, addr net.Addr, id string, target string) {
	entry := ConnLogEntry{
		Type:     typ,
		SourceIP: extractIP(addr),
		Target:   target,
		UserID:   id,
	}
	l.writeEntry(entry)
}

func (l *jsonConnLoggerImpl) LogDisconnect(addr net.Addr, id string, target string, tx, rx uint64, duration time.Duration, err error) {
	entry := ConnLogEntry{
		Type:       "disconnect",
		SourceIP:   extractIP(addr),
		Target:     target,
		TxBytes:    tx,
		RxBytes:    rx,
		DurationMs: duration.Milliseconds(),
		UserID:     id,
	}
	if err != nil {
		entry.Error = err.Error()
	}
	l.writeEntry(entry)
}

func (l *jsonConnLoggerImpl) LogTCPRequest(addr net.Addr, id, reqAddr string) {
	entry := ConnLogEntry{
		Type:     ConnTypeTCP,
		SourceIP: extractIP(addr),
		Target:   reqAddr,
		UserID:   id,
	}
	l.writeEntry(entry)
}

func (l *jsonConnLoggerImpl) LogTCPError(addr net.Addr, id, reqAddr string, err error) {
	entry := ConnLogEntry{
		Type:     ConnTypeTCP,
		SourceIP: extractIP(addr),
		Target:   reqAddr,
		UserID:   id,
	}
	if err != nil {
		entry.Error = err.Error()
	}
	l.writeEntry(entry)
}

func (l *jsonConnLoggerImpl) LogUDPRequest(addr net.Addr, id string, sessionID uint32, reqAddr string) {
	entry := ConnLogEntry{
		Type:     ConnTypeUDP,
		SourceIP: extractIP(addr),
		Target:   reqAddr,
		UserID:   id,
	}
	l.writeEntry(entry)
}

func (l *jsonConnLoggerImpl) LogUDPError(addr net.Addr, id string, sessionID uint32, err error) {
	entry := ConnLogEntry{
		Type:     ConnTypeUDP,
		SourceIP: extractIP(addr),
		UserID:   id,
	}
	if err != nil {
		entry.Error = err.Error()
	}
	l.writeEntry(entry)
}

func extractIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP.String()
	case *net.UDPAddr:
		return a.IP.String()
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return addr.String()
		}
		return host
	}
}
