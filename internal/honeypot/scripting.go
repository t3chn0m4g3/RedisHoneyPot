package honeypot

import (
	"crypto/sha1"
	"encoding/hex"
	"sync"
)

const maxCachedScripts = 1024

// scriptCache remembers scripts by SHA1 like Redis' script cache. Scripts are
// never executed.
type scriptCache struct {
	mu      sync.Mutex
	scripts map[string]string
	order   []string
}

func newScriptCache() *scriptCache {
	return &scriptCache{scripts: make(map[string]string)}
}

func scriptSHA1(body string) string {
	sum := sha1.Sum([]byte(body))
	return hex.EncodeToString(sum[:])
}

func (c *scriptCache) add(body string) string {
	sha := scriptSHA1(body)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.scripts[sha]; ok {
		return sha
	}
	if len(c.order) >= maxCachedScripts {
		delete(c.scripts, c.order[0])
		c.order = c.order[1:]
	}
	c.scripts[sha] = body
	c.order = append(c.order, sha)
	return sha
}

func (c *scriptCache) get(sha string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	body, ok := c.scripts[sha]
	return body, ok
}

func (c *scriptCache) bodies() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.order))
	for _, sha := range c.order {
		out = append(out, c.scripts[sha])
	}
	return out
}

func (c *scriptCache) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.order)
}

func (c *scriptCache) flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.scripts = make(map[string]string)
	c.order = nil
}
