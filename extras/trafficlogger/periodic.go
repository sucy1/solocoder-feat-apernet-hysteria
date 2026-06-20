package trafficlogger

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"go.etcd.io/bbolt"

	"github.com/apernet/hysteria/core/v2/server"
)

const (
	PeriodHourly  = "hourly"
	PeriodDaily   = "daily"
	PeriodMonthly = "monthly"

	defaultBucketPrefix = "traffic_stats"
)

type PeriodicTrafficStatsServer interface {
	server.TrafficLogger
	http.Handler
}

type PeriodicStatsConfig struct {
	DBPath     string
	Period     string
	Secret     string
	ListenAddr string
}

type periodicTrafficStatsServerImpl struct {
	mu          sync.RWMutex
	statsMap    map[string]*trafficStatsEntry
	onlineMap   map[string]int
	streamMap   map[server.HyStream]*server.StreamStats
	kickMap     map[string]struct{}
	secret      string
	period      string
	db          *bbolt.DB
	periodStart time.Time
	periodEnd   time.Time
}

func NewPeriodicTrafficStatsServer(cfg PeriodicStatsConfig) (PeriodicTrafficStatsServer, error) {
	db, err := bbolt.Open(cfg.DBPath, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open bolt db: %w", err)
	}

	period := cfg.Period
	if period == "" {
		period = PeriodDaily
	}

	s := &periodicTrafficStatsServerImpl{
		statsMap:  make(map[string]*trafficStatsEntry),
		onlineMap: make(map[string]int),
		streamMap: make(map[server.HyStream]*server.StreamStats),
		kickMap:   make(map[string]struct{}),
		secret:    cfg.Secret,
		period:    period,
		db:        db,
	}

	s.calculatePeriodBoundaries()
	if err := s.loadFromDB(); err != nil {
		return nil, err
	}

	go s.periodResetLoop()

	return s, nil
}

func (s *periodicTrafficStatsServerImpl) calculatePeriodBoundaries() {
	now := time.Now()
	switch s.period {
	case PeriodHourly:
		s.periodStart = time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, now.Location())
		s.periodEnd = s.periodStart.Add(time.Hour)
	case PeriodDaily:
		s.periodStart = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		s.periodEnd = s.periodStart.AddDate(0, 0, 1)
	case PeriodMonthly:
		s.periodStart = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
		s.periodEnd = s.periodStart.AddDate(0, 1, 0)
	default:
		s.periodStart = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		s.periodEnd = s.periodStart.AddDate(0, 0, 1)
	}
}

func (s *periodicTrafficStatsServerImpl) currentBucketName() string {
	return fmt.Sprintf("%s_%s", defaultBucketPrefix, s.periodStart.Format("20060102_150405"))
}

func (s *periodicTrafficStatsServerImpl) loadFromDB() error {
	return s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(s.currentBucketName()))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var entry trafficStatsEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return err
			}
			s.statsMap[string(k)] = &entry
			return nil
		})
	})
}

func (s *periodicTrafficStatsServerImpl) saveToDB() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(s.currentBucketName()))
		if err != nil {
			return err
		}
		s.mu.RLock()
		defer s.mu.RUnlock()
		for id, entry := range s.statsMap {
			data, err := json.Marshal(entry)
			if err != nil {
				return err
			}
			if err := b.Put([]byte(id), data); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *periodicTrafficStatsServerImpl) periodResetLoop() {
	for {
		now := time.Now()
		if now.After(s.periodEnd) {
			s.resetPeriod()
		}
		nextCheck := time.Until(s.periodEnd)
		if nextCheck <= 0 {
			nextCheck = time.Minute
		}
		time.Sleep(nextCheck)
	}
}

func (s *periodicTrafficStatsServerImpl) resetPeriod() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.saveToDB(); err != nil {
		fmt.Printf("failed to save stats to db before reset: %v\n", err)
	}

	s.statsMap = make(map[string]*trafficStatsEntry)
	s.calculatePeriodBoundaries()
}

func (s *periodicTrafficStatsServerImpl) LogTraffic(id string, tx, rx uint64) (ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, ok = s.kickMap[id]
	if ok {
		delete(s.kickMap, id)
		return false
	}

	entry, ok := s.statsMap[id]
	if !ok {
		entry = &trafficStatsEntry{}
		s.statsMap[id] = entry
	}
	entry.Tx += tx
	entry.Rx += rx

	return true
}

func (s *periodicTrafficStatsServerImpl) LogOnlineState(id string, online bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if online {
		s.onlineMap[id]++
	} else {
		s.onlineMap[id]--
		if s.onlineMap[id] <= 0 {
			delete(s.onlineMap, id)
		}
	}
}

func (s *periodicTrafficStatsServerImpl) TraceStream(stream server.HyStream, stats *server.StreamStats) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streamMap[stream] = stats
}

func (s *periodicTrafficStatsServerImpl) UntraceStream(stream server.HyStream) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.streamMap, stream)
}

func (s *periodicTrafficStatsServerImpl) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.secret != "" && r.Header.Get("Authorization") != s.secret {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/" {
		_, _ = w.Write([]byte(indexHTML))
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/traffic" {
		s.getTraffic(w, r)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/kick" {
		s.kick(w, r)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/online" {
		s.getOnline(w, r)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/dump/streams" {
		s.getDumpStreams(w, r)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/period" {
		s.getPeriod(w, r)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/history" {
		s.getHistory(w, r)
		return
	}
	http.NotFound(w, r)
}

func (s *periodicTrafficStatsServerImpl) getTraffic(w http.ResponseWriter, r *http.Request) {
	bClear, _ := strconv.ParseBool(r.URL.Query().Get("clear"))
	var jb []byte
	var err error
	if bClear {
		s.mu.Lock()
		jb, err = json.Marshal(s.statsMap)
		s.statsMap = make(map[string]*trafficStatsEntry)
		s.mu.Unlock()
	} else {
		s.mu.RLock()
		jb, err = json.Marshal(s.statsMap)
		s.mu.RUnlock()
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(jb)
}

func (s *periodicTrafficStatsServerImpl) getOnline(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	jb, err := json.Marshal(s.onlineMap)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(jb)
}

func (s *periodicTrafficStatsServerImpl) getDumpStreams(w http.ResponseWriter, r *http.Request) {
	var entries []dumpStreamEntry

	s.mu.RLock()
	entries = make([]dumpStreamEntry, len(s.streamMap))
	index := 0
	for stream, stats := range s.streamMap {
		entries[index].fromStreamStats(stream, stats)
		index++
	}
	s.mu.RUnlock()

	slicesSortFunc(entries, func(lhs, rhs dumpStreamEntry) int {
		if lhs.Auth < rhs.Auth {
			return -1
		}
		if lhs.Auth > rhs.Auth {
			return 1
		}
		if lhs.Connection < rhs.Connection {
			return -1
		}
		if lhs.Connection > rhs.Connection {
			return 1
		}
		if lhs.Stream < rhs.Stream {
			return -1
		}
		if lhs.Stream > rhs.Stream {
			return 1
		}
		return 0
	})

	accept := r.Header.Get("Accept")

	if containsString(accept, "text/plain") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintln(w, formatDumpStreamLine("State", "Auth", "Connection", "Stream", "Req-Addr", "Hooked-Req-Addr", "TX-Bytes", "RX-Bytes", "Lifetime", "Last-Active"))
		for _, entry := range entries {
			_, _ = fmt.Fprintln(w, entry.String())
		}
		return
	}

	wrapper := struct {
		Streams []dumpStreamEntry `json:"streams"`
	}{entries}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	err := json.NewEncoder(w).Encode(&wrapper)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *periodicTrafficStatsServerImpl) kick(w http.ResponseWriter, r *http.Request) {
	var ids []string
	err := json.NewDecoder(r.Body).Decode(&ids)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	for _, id := range ids {
		s.kickMap[id] = struct{}{}
	}
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func (s *periodicTrafficStatsServerImpl) getPeriod(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := map[string]interface{}{
		"period":      s.period,
		"periodStart": s.periodStart.Format(time.RFC3339),
		"periodEnd":   s.periodEnd.Format(time.RFC3339),
	}
	jb, err := json.Marshal(result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(jb)
}

func (s *periodicTrafficStatsServerImpl) getHistory(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	if period == "" {
		period = s.period
	}

	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	var history []map[string]interface{}
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bbolt.Bucket) error {
			bucketName := string(name)
			if !hasPrefix(bucketName, defaultBucketPrefix) {
				return nil
			}
			var totalTx, totalRx uint64
			var userCount int
			err := b.ForEach(func(k, v []byte) error {
				var entry trafficStatsEntry
				if err := json.Unmarshal(v, &entry); err != nil {
					return err
				}
				totalTx += entry.Tx
				totalRx += entry.Rx
				userCount++
				return nil
			})
			if err != nil {
				return err
			}
			history = append(history, map[string]interface{}{
				"bucket":   bucketName,
				"totalTx":  totalTx,
				"totalRx":  totalRx,
				"userCount": userCount,
			})
			if len(history) >= limit {
				return bbolt.ErrBucketNotFound
			}
			return nil
		})
	})
	if err != nil && err != bbolt.ErrBucketNotFound {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jb, err := json.Marshal(history)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(jb)
}

func (s *periodicTrafficStatsServerImpl) Close() error {
	if s.db != nil {
		_ = s.saveToDB()
		return s.db.Close()
	}
	return nil
}

func slicesSortFunc(slice []dumpStreamEntry, cmp func(a, b dumpStreamEntry) int) {
	for i := 0; i < len(slice); i++ {
		for j := i + 1; j < len(slice); j++ {
			if cmp(slice[i], slice[j]) > 0 {
				slice[i], slice[j] = slice[j], slice[i]
			}
		}
	}
}

func containsString(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && indexOfString(s, substr) >= 0
}

func indexOfString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
