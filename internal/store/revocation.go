package store

import "sync"

type Revocations interface {
	IsRevoked(string) bool
	Revoke(string)
}

type MemoryRevocations struct {
	mu sync.RWMutex
	m  map[string]bool
}

func NewMemoryRevocations() *MemoryRevocations { return &MemoryRevocations{m: map[string]bool{}} }
func (s *MemoryRevocations) IsRevoked(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m[id]
}
func (s *MemoryRevocations) Revoke(id string) { s.mu.Lock(); defer s.mu.Unlock(); s.m[id] = true }
