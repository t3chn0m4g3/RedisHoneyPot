package honeypot

import (
	"path"
	"sort"
	"sync"
)

type Store struct {
	mu  sync.RWMutex
	dbs map[int]map[string]string
}

func NewStore() *Store {
	return &Store{dbs: make(map[int]map[string]string)}
}

func (s *Store) Set(db int, key string, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db(db)[key] = value
}

func (s *Store) Get(db int, key string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	values := s.dbs[db]
	if values == nil {
		return "", false
	}
	value, ok := values[key]
	return value, ok
}

func (s *Store) Exists(db int, keys []string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	values := s.dbs[db]
	if values == nil {
		return 0
	}

	count := 0
	for _, key := range keys {
		if _, ok := values[key]; ok {
			count++
		}
	}
	return count
}

func (s *Store) Del(db int, keys []string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	values := s.dbs[db]
	if values == nil {
		return 0
	}

	count := 0
	for _, key := range keys {
		if _, ok := values[key]; ok {
			delete(values, key)
			count++
		}
	}
	return count
}

func (s *Store) Keys(db int, pattern string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	values := s.dbs[db]
	if values == nil {
		return nil
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		if matchRedisPattern(pattern, key) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func (s *Store) Size(db int) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.dbs[db])
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
	s.dbs = make(map[int]map[string]string)
	return count
}

func (s *Store) Keyspace() map[int]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keyspace := make(map[int]int)
	for db, values := range s.dbs {
		if len(values) > 0 {
			keyspace[db] = len(values)
		}
	}
	return keyspace
}

func (s *Store) db(db int) map[string]string {
	values := s.dbs[db]
	if values == nil {
		values = make(map[string]string)
		s.dbs[db] = values
	}
	return values
}

func matchRedisPattern(pattern string, key string) bool {
	if pattern == "*" {
		return true
	}
	match, err := path.Match(pattern, key)
	if err == nil {
		return match
	}
	return pattern == key
}
