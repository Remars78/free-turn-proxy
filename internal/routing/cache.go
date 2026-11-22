package routing

import (
	"net/netip"
	"sync"
	"time"
)

const (
	defaultMinTTL = 60 * time.Second
	defaultMaxTTL = 24 * time.Hour
	defaultMaxCap = 10000
)

// BypassCache потокобезопасно хранит IP-адреса, трафик к которым должен идти в обход туннеля.
type BypassCache struct {
	mu      sync.RWMutex
	entries map[netip.Addr]time.Time
	maxCap  int
}

// NewBypassCache создает новый кэш IP-адресов прямого доступа.
func NewBypassCache(maxCap int) *BypassCache {
	if maxCap <= 0 {
		maxCap = defaultMaxCap
	}
	return &BypassCache{
		entries: make(map[netip.Addr]time.Time, 256),
		maxCap:  maxCap,
	}
}

// Add добавляет IP-адрес в кэш с указанным TTL.
func (c *BypassCache) Add(ip netip.Addr, ttl time.Duration) {
	if !ip.IsValid() {
		return
	}
	if ttl < defaultMinTTL {
		ttl = defaultMinTTL
	} else if ttl > defaultMaxTTL {
		ttl = defaultMaxTTL
	}

	expiry := time.Now().Add(ttl)

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxCap {
		now := time.Now()
		for k, exp := range c.entries {
			if now.After(exp) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= c.maxCap {
			for k := range c.entries {
				delete(c.entries, k)
				break
			}
		}
	}

	c.entries[ip] = expiry
}

// Contains возвращает true, если IP-адрес находится в кэше и его срок действия не истек.
func (c *BypassCache) Contains(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	c.mu.RLock()
	exp, exists := c.entries[ip]
	c.mu.RUnlock()

	if !exists {
		return false
	}
	if time.Now().After(exp) {
		c.mu.Lock()
		delete(c.entries, ip)
		c.mu.Unlock()
		return false
	}
	return true
}

// Len возвращает количество активных записей.
func (c *BypassCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Clear очищает кэш.
func (c *BypassCache) Clear() {
	c.mu.Lock()
	clear(c.entries)
	c.mu.Unlock()
}
