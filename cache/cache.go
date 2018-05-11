// Package delta keeps a cache of connection info records, and supports updates,
// and delta generation.
package delta

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"syscall"

	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/tcp-info/nl-proto/tools"
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

func NewCache(raw io.WriteCloser, filter bool) *Cache {
	return &Cache{Records: make(map[uint32]*inetdiag.ParsedMessage, 1000)}
}

const countDiffTypes = false

var DiffCounts = make(map[string]int32, 20)

func count(name string) {
	if countDiffTypes {
		DiffCounts[name]++
	}
}

func IsSame(pm *inetdiag.ParsedMessage, other *inetdiag.ParsedMessage) bool {
	diff := len(pm.Attributes) != len(other.Attributes)

	// TODO - this is expensive.  Probably shouldn't use it.
	if *pm.InetDiagMsg != *other.InetDiagMsg {
		//if len(idmDiff) > 0 {
		count("idm")

		if pm.InetDiagMsg.IDiagExpires != other.InetDiagMsg.IDiagExpires {
			count("expires")
		}
		if pm.InetDiagMsg.IDiagWqueue != other.InetDiagMsg.IDiagWqueue {
			count("wqueue")
		}

		tmp := *other.InetDiagMsg
		tmp.IDiagExpires = pm.InetDiagMsg.IDiagExpires

		if *pm.InetDiagMsg != tmp {
			//log.Println(otherDiff)
			count("idm ignoring expires")
			diff = true
		}
	}

	// log.Println(len(pm.Attributes), len(other.Attributes))
	for tp := range pm.Attributes {
		now := pm.Attributes[tp]
		past := other.Attributes[tp]
		if now == nil && past == nil {
			continue
		}
		if now == nil || past == nil {
			count("mismatchedAttr")
			diff = true
			continue
		}
		if len(now.Value) != len(past.Value) {
			count(fmt.Sprintf("AttrLength %d", now.Attr.Type))
			diff = true
		} else {
			// go run play.go -v -reps=300 2>&1 | grep cookie | sed -e 's/.*cookie/cookie/;' | sed -e 's/last_data_sent.*pmtu/pmtu/;' | sed -e 's/expires:.* inode:/inode:/;' | sort | uniq | wc
			switch tp {
			case inetdiag.INET_DIAG_MEMINFO:
				if 0 != bytes.Compare(now.Value, past.Value) {
					count("MemInfo")
					diff = true
				}
			case inetdiag.INET_DIAG_INFO:
				if 0 != bytes.Compare(now.Value[:tools.LastDataSentOffset], past.Value[:tools.LastDataSentOffset]) {
					count("Early")
					diff = true
				}
				if 0 != bytes.Compare(now.Value[tools.LastDataSentOffset:tools.PmtuOffset], past.Value[tools.LastDataSentOffset:tools.PmtuOffset]) {
					count("Last...")
					// TODO - if FineGrained
					// diff = true
				}
				if 0 != bytes.Compare(now.Value[tools.PmtuOffset:], past.Value[tools.PmtuOffset:]) {
					count("Late")
					diff = true
				}
			case inetdiag.INET_DIAG_VEGASINFO:
				if 0 != bytes.Compare(now.Value, past.Value) {
					count("Vegas")
					diff = true
				}
			case inetdiag.INET_DIAG_CONG:
				if 0 != bytes.Compare(now.Value, past.Value) {
					count("Cong")
					diff = true
				}
			case inetdiag.INET_DIAG_TOS:
				if 0 != bytes.Compare(now.Value, past.Value) {
					count("TOS")
					diff = true
				}
			case inetdiag.INET_DIAG_TCLASS:
				if 0 != bytes.Compare(now.Value, past.Value) {
					count("TCLASS")
					diff = true
				}
			case inetdiag.INET_DIAG_SKMEMINFO:
				if 0 != bytes.Compare(now.Value, past.Value) {
					count("SocketMemInfo")
					diff = true
				}
			case inetdiag.INET_DIAG_SHUTDOWN:
				if 0 != bytes.Compare(now.Value, past.Value) {
					count("SHUTDOWN")
					diff = true
				}
			case inetdiag.INET_DIAG_DCTCPINFO:
				if 0 != bytes.Compare(now.Value, past.Value) {
					count("DCTPC")
					diff = true
				}
			case inetdiag.INET_DIAG_PROTOCOL:
				if 0 != bytes.Compare(now.Value, past.Value) {
					count("Protocol")
					diff = true
				}
			case inetdiag.INET_DIAG_SKV6ONLY:
				if 0 != bytes.Compare(now.Value, past.Value) {
					count("SK6")
					diff = true
				}
			default:
				if 0 != bytes.Compare(now.Value, past.Value) {
					count("Other")
					diff = true
				}
			}
		}
	}
	return !diff
}

// Update swaps msg with the cache contents, and returns true if there is
// any meaningful change in the content, aside from trivial count updates.
// TODO - also return the local network address?
func (c *Cache) Update(msg *syscall.NetlinkMessage) (*inetdiag.ParsedMessage, error) {
	pm, err := inetdiag.Parse(msg, true)

	if err != nil {
		return nil, err
	}

	if pm == nil {
		return nil, nil
	}

	current, ok := c.Records[pm.InetDiagMsg.IDiagInode]
	c.Records[pm.InetDiagMsg.IDiagInode] = pm

	if !ok {
		// TODO  log an error and inc monitoring.
		return pm, nil
	}

	same := IsSame(pm, current)

	if same {
		return nil, nil
	} else {
		return pm, nil
	}
}
