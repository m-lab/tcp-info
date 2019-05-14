// Package netlink contains the bare minimum needed to partially parse netlink messages.
package netlink

import (
	"errors"
	"log"
	"syscall"
	"unsafe"

	"github.com/m-lab/tcp-info/inetdiag"
	"golang.org/x/sys/unix"
)

// Error types.
var (
	ErrNotType20   = errors.New("NetlinkMessage wrong type")
	ErrParseFailed = errors.New("Unable to parse InetDiagMsg")
)

/*********************************************************************************************
*                         Low level netlink message stuff
*********************************************************************************************/

// RawInetDiagMsg holds the []byte representation of an InetDiagMsg
type RawInetDiagMsg []byte

// Parse returns the InetDiagMsg itself
// Modified from original to also return attribute data array.
func (raw RawInetDiagMsg) Parse() (*inetdiag.InetDiagMsg, error) {
	align := rtaAlignOf(int(unsafe.Sizeof(inetdiag.InetDiagMsg{})))
	if len(raw) < align {
		return nil, ErrParseFailed
	}
	return (*inetdiag.InetDiagMsg)(unsafe.Pointer(&raw[0])), nil
}

func splitInetDiagMsg(data []byte) (RawInetDiagMsg, []byte) {
	align := rtaAlignOf(int(unsafe.Sizeof(inetdiag.InetDiagMsg{})))
	if len(data) < align {
		log.Println("Wrong length", len(data), "<", align)
		log.Println(data)
		return nil, nil
	}
	return RawInetDiagMsg(data[:align]), data[align:]
}

// ParseRouteAttr parses a byte array into slice of NetlinkRouteAttr struct.
// Derived from "github.com/vishvananda/netlink/nl/nl_linux.go"
func ParseRouteAttr(b []byte) ([]syscall.NetlinkRouteAttr, error) {
	var attrs []syscall.NetlinkRouteAttr
	for len(b) >= unix.SizeofRtAttr {
		a, vbuf, alen, err := netlinkRouteAttrAndValue(b)
		if err != nil {
			return nil, err
		}
		ra := syscall.NetlinkRouteAttr{Attr: syscall.RtAttr(*a), Value: vbuf[:int(a.Len)-unix.SizeofRtAttr]}
		attrs = append(attrs, ra)
		b = b[alen:]
	}
	return attrs, nil
}

// rtaAlignOf rounds the length of a netlink route attribute up to align it properly.
func rtaAlignOf(attrlen int) int {
	return (attrlen + unix.RTA_ALIGNTO - 1) & ^(unix.RTA_ALIGNTO - 1)
}

func netlinkRouteAttrAndValue(b []byte) (*unix.RtAttr, []byte, int, error) {
	a := (*unix.RtAttr)(unsafe.Pointer(&b[0]))
	if int(a.Len) < unix.SizeofRtAttr || int(a.Len) > len(b) {
		return nil, nil, 0, unix.EINVAL
	}
	return a, b[unix.SizeofRtAttr:], rtaAlignOf(int(a.Len)), nil
}
