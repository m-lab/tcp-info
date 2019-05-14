// Package netlink contains the bare minimum needed to partially parse netlink messages.
package netlink

import (
	"errors"
	"syscall"
	"unsafe"
)

/*******************************************************************************************/
/*   These are hard coded, because darwin doesn't include the appropriate linux headers.   */
/*******************************************************************************************/

type NlMsghdr struct {
	Len   uint32
	Type  uint16
	Flags uint16
	Seq   uint32
	Pid   uint32
}

// NetlinkMessage represents a netlink message.
type NetlinkMessage struct {
	Header NlMsghdr
	Data   []byte
}

type RtAttr struct {
	Len  uint16
	Type uint16
}

// NetlinkRouteAttr represents a netlink route attribute.
type NetlinkRouteAttr struct {
	Attr  RtAttr
	Value []byte
}

const (
	RTA_ALIGNTO    = 4
	SizeofNlMsghdr = 0x10
	SizeofNlAttr   = 0x4
	SizeofRtAttr   = 0x4

	EINVAL = syscall.Errno(0x16)
)

/*******************************************************************************************/

// Error types.
var (
	ErrNotType20   = errors.New("NetlinkMessage wrong type")
	ErrParseFailed = errors.New("Unable to parse InetDiagMsg")
)

/*********************************************************************************************
*                         Low level netlink message stuff
*********************************************************************************************/

// rtaAlignOf rounds the length of a netlink route attribute up to align it properly.
func rtaAlignOf(attrlen int) int {
	return (attrlen + RTA_ALIGNTO - 1) & ^(RTA_ALIGNTO - 1)
}

func netlinkRouteAttrAndValue(b []byte) (*RtAttr, []byte, int, error) {
	a := (*RtAttr)(unsafe.Pointer(&b[0]))
	if int(a.Len) < SizeofRtAttr || int(a.Len) > len(b) {
		return nil, nil, 0, EINVAL
	}
	return a, b[SizeofRtAttr:], rtaAlignOf(int(a.Len)), nil
}
