// Package cache keeps a cache of connection info records.
package cache

import (
	"errors"

	"github.com/m-lab/tcp-info/inetdiag"
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
	current  map[uint32]*inetdiag.ParsedMessage // Cache of most recent messages.
	previous map[uint32]*inetdiag.ParsedMessage // Cache of previous round of messages.
}

// NewCache creates a cache object with capacity of 1000.
func NewCache() *Cache {
	return &Cache{current: make(map[uint32]*inetdiag.ParsedMessage, 1000),
		previous: make(map[uint32]*inetdiag.ParsedMessage, 0)}
}

// Update swaps msg with the cache contents, and returns the evicted value.
func (c *Cache) Update(msg *inetdiag.ParsedMessage) *inetdiag.ParsedMessage {
	inode := msg.InetDiagMsg.IDiagInode
	c.current[inode] = msg
	evicted, ok := c.previous[inode]
	if ok {
		delete(c.previous, inode)
	}
	return evicted
}

// EndCycle marks the completion of updates from one set of netlink messages.
// It returns all messages that did not have corresponding inodes in the most recent
// batch of messages.
func (c *Cache) EndCycle() map[uint32]*inetdiag.ParsedMessage {
	tmp := c.previous
	c.previous = c.current
	// Allocate a bit more than last time, to accommodate new connections.
	c.current = make(map[uint32]*inetdiag.ParsedMessage, len(c.previous)+len(c.previous)/10+10)
	return tmp
}
