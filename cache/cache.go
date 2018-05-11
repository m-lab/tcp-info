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
// TODO - need to remove entries from cache when they are not present in netlink messages.
type Cache struct {
	// Map from inode to ParsedMessage
	current map[uint32]*inetdiag.ParsedMessage
	past    map[uint32]*inetdiag.ParsedMessage
}

// NewCache creates a cache object with capacity of 1000.
func NewCache() *Cache {
	return &Cache{current: make(map[uint32]*inetdiag.ParsedMessage, 1000),
		past: make(map[uint32]*inetdiag.ParsedMessage, 1000)}
}

// Update swaps msg with the cache contents, and returns the cached value.
func (c *Cache) Update(msg *inetdiag.ParsedMessage) *inetdiag.ParsedMessage {
	inode := msg.InetDiagMsg.IDiagInode
	c.current[inode] = msg
	tmp, ok := c.past[inode]
	if ok {
		delete(c.past, inode)
	}
	return tmp
}

// EndCycle marks the completion of updates from the kernel messages.
// It returns all messages that did not have corresponding inodes in the most recent
// batch of records from the kernel.
func (c *Cache) EndCycle() map[uint32]*inetdiag.ParsedMessage {
	tmp := c.past
	c.past = c.current
	c.current = make(map[uint32]*inetdiag.ParsedMessage, len(c.past)+10)
	return tmp
}
