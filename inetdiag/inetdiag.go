package inetdiag

// Pretty basic code slightly adapted from
// Copied from https://gist.github.com/gwind/05f5f649d93e6015cf47ffa2b2fd9713
// Original source no longer available at https://github.com/eleme/netlink/blob/master/inetdiag.go

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	tcpinfo "github.com/m-lab/tcp-info/nl-proto"
	"github.com/vishvananda/netlink/nl"
)

// Error types.
var (
	ErrParseFailed = errors.New("Unable to parse InetDiagMsg")
	ErrNotType20   = errors.New("NetlinkMessage wrong type")
)

// Constants from linux.
const (
	TCPDIAG_GETSOCK     = 18 // linux/inet_diag.h
	SOCK_DIAG_BY_FAMILY = 20 // linux/sock_diag.h
)

// inet_diag.h
const (
	INET_DIAG_NONE = iota
	INET_DIAG_MEMINFO
	INET_DIAG_INFO
	INET_DIAG_VEGASINFO
	INET_DIAG_CONG
	INET_DIAG_TOS
	INET_DIAG_TCLASS
	INET_DIAG_SKMEMINFO
	INET_DIAG_SHUTDOWN
	INET_DIAG_DCTCPINFO
	INET_DIAG_PROTOCOL
	INET_DIAG_SKV6ONLY
	INET_DIAG_LOCALS
	INET_DIAG_PEERS
	INET_DIAG_PAD
	INET_DIAG_MARK
	INET_DIAG_BBRINFO
	INET_DIAG_CLASS_ID
	INET_DIAG_MD5SIG
	INET_DIAG_MAX
)

var diagFamilyMap = map[uint8]string{
	syscall.AF_INET:  "tcp",
	syscall.AF_INET6: "tcp6",
}

type be16 [2]byte

func (v be16) Int() int {
	// (*(*[SizeofInetDiagReqV2]byte)(unsafe.Pointer(req)))[:]
	v2 := (*(*uint16)(unsafe.Pointer(&v)))
	return int(nl.Swap16(v2))
}

type be32 [4]byte

// InetDiagSockID is the binary linux representation of a socket.
// from linux/inet_diag.h
type InetDiagSockID struct {
	IDiagSPort  [2]byte // This appears to be byte swapped.  Is it from a network byte ordered field in stack?
	IDiagDPort  [2]byte
	IDiagSrc    [16]byte
	IDiagDst    [16]byte
	IDiagIf     uint32
	IDiagCookie [2]uint32
}

func (x be32) isZero() bool {
	for i := range x {
		if x[i] != 0 {
			return false
		}
	}
	return true
}

func (x be32) isSame(y be32) bool {
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func isZero(xx [4]be32) bool {
	for i := range xx {
		if !xx[i].isZero() {
			return false
		}
	}
	return true
}

// IsLocal compares source and destination.  If they are the same,
// we assume this is loopback and return true.
func (id *InetDiagSockID) IsLocal() (bool, error) {
	src := id.IDiagSrc
	dst := id.IDiagDst

	if len(src) != len(dst) {
		return false, errors.New("invalid socket id")
	}

	if isZero(src) {
		return true, nil
	}
	if isZero(dst) {
		return true, nil
	}

	for i := range src {
		if !src[i].isSame(dst[i]) {
			return false, nil
		}
	}
	return true, nil
}

func (id *InetDiagSockID) SrcIPv4() net.IP {
	return ipv4(id.IDiagSrc[0])
}

func (id *InetDiagSockID) DstIPv4() net.IP {
	return ipv4(id.IDiagDst[0])
}

func (id *InetDiagSockID) SrcIPv6() net.IP {
	return ipv6(id.IDiagSrc)
}

func (id *InetDiagSockID) DstIPv6() net.IP {
	return ipv6(id.IDiagDst)
}

func (id *InetDiagSockID) SrcIP() net.IP {
	return ip(id.IDiagSrc)
}

func (id *InetDiagSockID) DstIP() net.IP {
	return ip(id.IDiagDst)
}

func ip(bytes [4]be32) net.IP {
	if isIpv6(bytes) {
		return ipv6(bytes)
	} else {
		return ipv4(bytes[0])
	}
}

func isIpv6(original [4]be32) bool {
	for i := 1; i < 4; i++ {
		for j := 0; j < 4; j++ {
			if original[i][j] != 0 {
				return true
			}
		}
	}
	return false
}

func ipv4(original [16]byte) net.IP {
	return net.IPv4(original[0], original[1], original[2], original[3]).To4()
}

func ipv6(original [4]be32) net.IP {
	ip := make(net.IP, net.IPv6len)
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			ip[4*i+j] = original[i][j]
		}
	}
	return ip
}

func (id *InetDiagSockID) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d (%d)", id.SrcIP().String(), id.SPort(), id.DstIP().String(), id.DPort(), id.IDiagCookie)
}

type InetDiagReqV2 struct {
	SDiagFamily   uint8
	SDiagProtocol uint8
	IDiagExt      uint8
	Pad           uint8
	IDiagStates   uint32
	Id            InetDiagSockID
}

func (req *InetDiagReqV2) Serialize() []byte {
	return (*(*[SizeofInetDiagReqV2]byte)(unsafe.Pointer(req)))[:]
}

func (req *InetDiagReqV2) Len() int {
	return SizeofInetDiagReqV2
}

func NewInetDiagReqV2(family, protocol uint8, states uint32) *InetDiagReqV2 {
	return &InetDiagReqV2{
		SDiagFamily:   family,
		SDiagProtocol: protocol,
		IDiagStates:   states,
	}
}

type InetDiagMsg struct {
	IDiagFamily  uint8
	IDiagState   uint8
	IDiagTimer   uint8
	IDiagRetrans uint8
	Id           InetDiagSockID
	IDiagExpires uint32
	IDiagRqueue  uint32
	IDiagWqueue  uint32
	IDiagUid     uint32
	IDiagInode   uint32
}

// SPort returns the host byte ordered port.
// In general, Netlink is supposed to use host byte order, but this seems to be an exception.
// Perhaps Netlink is reading a tcp stack structure that holds the port in network byte order.
func (id *InetDiagSockID) SPort() uint16 {
	return binary.BigEndian.Uint16(id.IDiagSPort[:])
}

// DPort returns the host byte ordered port.
// In general, Netlink is supposed to use host byte order, but this seems to be an exception.
// Perhaps Netlink is reading a tcp stack structure that holds the port in network byte order.
func (id *InetDiagSockID) DPort() uint16 {
	return binary.BigEndian.Uint16(id.IDiagDPort[:])
}

func (msg *InetDiagMsg) String() string {
	return fmt.Sprintf("%s, %s, %s", diagFamilyMap[msg.IDiagFamily], tcpinfo.TCPState(msg.IDiagState), msg.ID.String())
}

// ParseInetDiagMsg returns the InetDiagMsg itself, and the aligned byte array containing the message content.
// Modified from original to also return attribute data array.
func ParseInetDiagMsg(data []byte) (*InetDiagMsg, []byte) {
	align := rtaAlignOf(int(unsafe.Sizeof(InetDiagMsg{})))
	if len(data) < align {
		log.Println("Wrong length", len(data), "<", align)
		log.Println(data)
		return nil, nil
	}
	return (*InetDiagMsg)(unsafe.Pointer(&data[0])), data[rtaAlignOf(int(unsafe.Sizeof(InetDiagMsg{}))):]
}

// ParsedMessage is a container for parsed InetDiag messages and attributes.
type ParsedMessage struct {
	Header      syscall.NlMsghdr
	InetDiagMsg *InetDiagMsg
	Attributes  [INET_DIAG_MAX]*syscall.NetlinkRouteAttr
}

// Parse parsed the NetlinkMessage into a ParsedMessage.  If skipLocal is true, it will return nil for
// loopback, local unicast, multicast, and unspecified connections.
func Parse(msg *syscall.NetlinkMessage, skipLocal bool) (*ParsedMessage, error) {
	if msg.Header.Type != 20 {
		return nil, ErrNotType20
	}
	idm, attrBytes := ParseInetDiagMsg(msg.Data)
	if idm == nil {
		return nil, ErrParseFailed
	}
	if skipLocal {
		srcIP := idm.ID.SrcIP()
		if srcIP.IsLoopback() || srcIP.IsLinkLocalUnicast() || srcIP.IsMulticast() || srcIP.IsUnspecified() {
			return nil, nil
		}
		dstIP := idm.ID.DstIP()
		if dstIP.IsLoopback() || dstIP.IsLinkLocalUnicast() || dstIP.IsMulticast() || dstIP.IsUnspecified() {
			return nil, nil
		}
	}
	parsedMsg := ParsedMessage{Header: msg.Header, InetDiagMsg: idm}
	attrs, err := ParseRouteAttr(attrBytes)
	if err != nil {
		return nil, err
	}
	for i := range attrs {
		parsedMsg.Attributes[attrs[i].Attr.Type] = &attrs[i]
	}
	return &parsedMsg, nil
}

/*********************************************************************************************/
/*             Copied from "github.com/vishvananda/netlink/nl/nl_linux.go"                   */
/*********************************************************************************************/

// ParseRouteAttr parses a byte array into a NetlinkRouteAttr struct.
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
