package netlink

import "time"

// MessageBlock contains timestamps and message arrays for v4 and v6 from a single collection cycle.
type MessageBlock struct {
	V4Time     time.Time         // Time at which netlink message block was received.
	V4Messages []*NetlinkMessage // Array of raw messages.

	V6Time     time.Time
	V6Messages []*NetlinkMessage
}
