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
	Records map[uint32]*inetdiag.ParsedMessage
}

// NewCache creates a cache object with capacity of 1000.
func NewCache() *Cache {
	return &Cache{Records: make(map[uint32]*inetdiag.ParsedMessage, 1000)}
}

// Swap swaps msg with the cache contents, and returns the cached value.
func (c *Cache) Swap(msg *inetdiag.ParsedMessage) (*inetdiag.ParsedMessage, error) {
	current := c.Records[msg.InetDiagMsg.IDiagInode]
	c.Records[msg.InetDiagMsg.IDiagInode] = msg
	return current, nil
}
