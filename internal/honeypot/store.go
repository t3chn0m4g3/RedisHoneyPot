package honeypot

import (
	"sort"
	"sync"
	"time"
)

type storeEntry struct {
	value    string
	expireAt time.Time
}

func (e storeEntry) expired(now time.Time) bool {
	return !e.expireAt.IsZero() && !now.Before(e.expireAt)
}

// Store is the in-memory string keyspace. Expired keys are removed lazily on
// access, like Redis' passive expiry.
type Store struct {
	mu          sync.Mutex
	dbs         map[int]map[string]storeEntry
	expiredKeys uint64
}

type keyspaceStats struct {
	keys    int
	expires int
}

func NewStore() *Store {
	return &Store{dbs: make(map[int]map[string]storeEntry)}
}

// lookup returns the live entry for key, deleting it when it has expired.
// The caller must hold s.mu.
func (s *Store) lookup(db int, key string, now time.Time) (storeEntry, bool) {
	values := s.dbs[db]
	if values == nil {
		return storeEntry{}, false
	}
	entry, ok := values[key]
	if !ok {
		return storeEntry{}, false
	}
	if entry.expired(now) {
		delete(values, key)
		s.expiredKeys++
		return storeEntry{}, false
	}
	return entry, true
}

// Set stores value. A zero expireAt removes any TTL unless keepTTL is set.
func (s *Store) Set(db int, key string, value string) {
	s.SetWithExpiry(db, key, value, time.Time{}, false)
}

func (s *Store) SetWithExpiry(db int, key string, value string, expireAt time.Time, keepTTL bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if keepTTL {
		if old, ok := s.lookup(db, key, time.Now()); ok {
			expireAt = old.expireAt
		}
	}
	s.db(db)[key] = storeEntry{value: value, expireAt: expireAt}
}

func (s *Store) Get(db int, key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.lookup(db, key, time.Now())
	return entry.value, ok
}

// TTL returns the remaining lifetime; hasTTL is false for persistent keys.
func (s *Store) TTL(db int, key string) (remaining time.Duration, exists bool, hasTTL bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	entry, ok := s.lookup(db, key, now)
	if !ok {
		return 0, false, false
	}
	if entry.expireAt.IsZero() {
		return 0, true, false
	}
	return entry.expireAt.Sub(now), true, true
}

// Expire sets an absolute expiry; it reports whether the key existed.
func (s *Store) Expire(db int, key string, expireAt time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	entry, ok := s.lookup(db, key, now)
	if !ok {
		return false
	}
	if !expireAt.After(now) {
		delete(s.dbs[db], key)
		return true
	}
	entry.expireAt = expireAt
	s.dbs[db][key] = entry
	return true
}

func (s *Store) Persist(db int, key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.lookup(db, key, time.Now())
	if !ok || entry.expireAt.IsZero() {
		return false
	}
	entry.expireAt = time.Time{}
	s.dbs[db][key] = entry
	return true
}

func (s *Store) Exists(db int, keys []string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	count := 0
	for _, key := range keys {
		if _, ok := s.lookup(db, key, now); ok {
			count++
		}
	}
	return count
}

func (s *Store) Del(db int, keys []string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	count := 0
	for _, key := range keys {
		if _, ok := s.lookup(db, key, now); ok {
			delete(s.dbs[db], key)
			count++
		}
	}
	return count
}

func (s *Store) Keys(db int, pattern string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	values := s.dbs[db]
	if values == nil {
		return nil
	}

	now := time.Now()
	allKeys := pattern == "*"
	keys := make([]string, 0, len(values))
	for key := range values {
		if _, ok := s.lookup(db, key, now); !ok {
			continue
		}
		if allKeys || stringMatch(pattern, key, false) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func (s *Store) Size(db int) int {
	return s.Keyspace()[db].keys
}

func (s *Store) FlushDB(db int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := len(s.dbs[db])
	delete(s.dbs, db)
	return count
}

func (s *Store) FlushAll() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, values := range s.dbs {
		count += len(values)
	}
	s.dbs = make(map[int]map[string]storeEntry)
	return count
}

// Keyspace returns live key and expiry counts per non-empty database.
func (s *Store) Keyspace() map[int]keyspaceStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	keyspace := make(map[int]keyspaceStats)
	for db, values := range s.dbs {
		var stats keyspaceStats
		for key, entry := range values {
			if entry.expired(now) {
				delete(values, key)
				s.expiredKeys++
				continue
			}
			stats.keys++
			if !entry.expireAt.IsZero() {
				stats.expires++
			}
		}
		if stats.keys > 0 {
			keyspace[db] = stats
		}
	}
	return keyspace
}

// ExpiredKeys returns how many keys expired so far.
func (s *Store) ExpiredKeys() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.expiredKeys
}

type snapshotEntry struct {
	key      string
	value    string
	expireAt time.Time
}

// Snapshot returns live entries per database, sorted by key.
func (s *Store) Snapshot() map[int][]snapshotEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	out := make(map[int][]snapshotEntry)
	for db, values := range s.dbs {
		for key, entry := range values {
			if entry.expired(now) {
				continue
			}
			out[db] = append(out[db], snapshotEntry{key: key, value: entry.value, expireAt: entry.expireAt})
		}
		sort.Slice(out[db], func(i, j int) bool { return out[db][i].key < out[db][j].key })
	}
	return out
}

func (s *Store) db(db int) map[string]storeEntry {
	values := s.dbs[db]
	if values == nil {
		values = make(map[string]storeEntry)
		s.dbs[db] = values
	}
	return values
}
