// Package cache keeps a cache of connection info records.
// Cache is NOT threadsafe.
package cache

import (
	"errors"

	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/tcp-info/metrics"
)

// Package error messages
var (
	ErrInetDiagParseFailed = errors.New("Error parsing inetdiag message")
	ErrLocal               = errors.New("Connection is loopback")
	ErrUnknownMessageType  = errors.New("Unknown netlink message type")
)

// Cache is a cache of all connection status.
type Cache struct {
	// Map from inode to ParsedMessage
	current  map[uint64]*inetdiag.ParsedMessage // Cache of most recent messages.
	previous map[uint64]*inetdiag.ParsedMessage // Cache of previous round of messages.
	cycles   int64
}

// NewCache creates a cache object with capacity of 1000.
// The map size is adjusted on every sampling round, but we have to start somewhere.
func NewCache() *Cache {
	return &Cache{current: make(map[uint64]*inetdiag.ParsedMessage, 1000),
		previous: make(map[uint64]*inetdiag.ParsedMessage, 0)}
}

// Update swaps msg with the cache contents, and returns the evicted value.
func (c *Cache) Update(msg *inetdiag.ParsedMessage) *inetdiag.ParsedMessage {
	cookie := msg.InetDiagMsg.ID.Cookie()
	c.current[cookie] = msg
	evicted, ok := c.previous[cookie]
	if ok {
		delete(c.previous, cookie)
	}
	return evicted
}

// EndCycle marks the completion of updates from one set of netlink messages.
// It returns all messages that did not have corresponding inodes in the most recent
// batch of messages.
func (c *Cache) EndCycle() map[uint64]*inetdiag.ParsedMessage {
	metrics.CacheSizeHistogram.Observe(float64(len(c.current)))
	tmp := c.previous
	c.previous = c.current
	// Allocate a bit more than previous size, to accommodate new connections.
	// This will grow and shrink with the number of active connections, but
	// minimize reallocation.
	c.current = make(map[uint64]*inetdiag.ParsedMessage, len(c.previous)+len(c.previous)/10+10)
	c.cycles++
	return tmp
}

// CycleCount returns the number of times EndCycle() has been called.
func (c *Cache) CycleCount() int64 {
	// Don't need a prometheus counter, because we already have the count of CacheSizeHistogram observations.
	return c.cycles
}
