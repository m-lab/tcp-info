// Package inetdiag provides basic structs and utilities for INET_DIAG messaages.
// Based on uapi/linux/inet_diag.h.
package inetdiag

// Pretty basic code slightly adapted from code copied from
// https://gist.github.com/gwind/05f5f649d93e6015cf47ffa2b2fd9713
// Original source no longer available at https://github.com/eleme/netlink/blob/master/inetdiag.go

// Adaptations are Copyright 2018 M-Lab Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/* IMPORTANT NOTES
This 2002 article describes Netlink Sockets
https://pdfs.semanticscholar.org/6efd/e161a2582ba5846e4b8fea5a53bc305a64f3.pdf

"Netlink messages are aligned to 32 bits and, generally speaking, they contain data that is
expressed in host-byte order"
*/

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	tcpinfo "github.com/m-lab/tcp-info/nl-proto"
)

// Error types.
var (
	ErrParseFailed = errors.New("Unable to parse InetDiagMsg")
	ErrNotType20   = errors.New("NetlinkMessage wrong type")
)

// Constants from linux.
const (
	TCPDIAG_GETSOCK     = 18 // uapi/linux/inet_diag.h
	SOCK_DIAG_BY_FAMILY = 20 // uapi/linux/sock_diag.h
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

// InetDiagSockID is the binary linux representation of a socket, as in linux/inet_diag.h
// Linux code comments indicate this struct uses the network byte order!!!
type InetDiagSockID struct {
	IDiagSPort  [2]byte
	IDiagDPort  [2]byte
	IDiagSrc    [16]byte
	IDiagDst    [16]byte
	IDiagIf     [4]byte
	IDiagCookie [8]byte
}

// Interface returns the interface number.
func (id *InetDiagSockID) Interface() uint32 {
	return binary.BigEndian.Uint32(id.IDiagIf[:])
}

// SrcIP returns a golang net encoding of source address.
func (id *InetDiagSockID) SrcIP() net.IP {
	return ip(id.IDiagSrc)
}

// DstIP returns a golang net encoding of destination address.
func (id *InetDiagSockID) DstIP() net.IP {
	return ip(id.IDiagDst)
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

// Cookie returns the SockID's 64 bit unsigned cookie.
func (id *InetDiagSockID) Cookie() uint64 {
	// This is pretty arbitrary, and may not match across operating systems.
	return binary.BigEndian.Uint64(id.IDiagCookie[:])
}

// TODO should use more net.IP code instead of custom code.
func ip(bytes [16]byte) net.IP {
	if isIpv6(bytes) {
		return ipv6(bytes)
	} else {
		return ipv4(bytes)
	}
}

func isIpv6(original [16]byte) bool {
	for i := 4; i < 16; i++ {
		if original[i] != 0 {
			return true
		}
	}
	return false
}

func ipv4(original [16]byte) net.IP {
	return net.IPv4(original[0], original[1], original[2], original[3]).To4()
}

func ipv6(original [16]byte) net.IP {
	return original[:]
}

func (id *InetDiagSockID) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d", id.SrcIP().String(), id.SPort(), id.DstIP().String(), id.DPort())
}

// InetDiagReqV2 is the Netlink request struct, as in linux/inet_diag.h
// Note that netlink messages use host byte ordering, unless NLA_F_NET_BYTEORDER flag is present.
type InetDiagReqV2 struct {
	SDiagFamily   uint8
	SDiagProtocol uint8
	IDiagExt      uint8
	Pad           uint8
	IDiagStates   uint32
	ID            InetDiagSockID
}

// SizeofInetDiagReqV2 is the size of the struct.
// TODO should we just make this explicit in the code?
const SizeofInetDiagReqV2 = int(unsafe.Sizeof(InetDiagReqV2{})) // Should be 0x38

// Serialize is provided for json serialization?
// TODO - should use binary functions instead?
func (req *InetDiagReqV2) Serialize() []byte {
	return (*(*[SizeofInetDiagReqV2]byte)(unsafe.Pointer(req)))[:]
}

// Len is provided for json serialization?
func (req *InetDiagReqV2) Len() int {
	return SizeofInetDiagReqV2
}

// NewInetDiagReqV2 creates a new request.
func NewInetDiagReqV2(family, protocol uint8, states uint32) *InetDiagReqV2 {
	return &InetDiagReqV2{
		SDiagFamily:   family,
		SDiagProtocol: protocol,
		IDiagStates:   states,
	}
}

// InetDiagMsg is the linux binary representation of a InetDiag message header, as in linux/inet_diag.h
// Note that netlink messages use host byte ordering, unless NLA_F_NET_BYTEORDER flag is present.
type InetDiagMsg struct {
	IDiagFamily  uint8
	IDiagState   uint8
	IDiagTimer   uint8
	IDiagRetrans uint8
	ID           InetDiagSockID
	IDiagExpires uint32
	IDiagRqueue  uint32
	IDiagWqueue  uint32
	IDiagUID     uint32
	IDiagInode   uint32
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
	Timestamp   time.Time
	Header      syscall.NlMsghdr
	InetDiagMsg *InetDiagMsg
	Attributes  [INET_DIAG_MAX]*syscall.NetlinkRouteAttr
}

// Parse parses the NetlinkMessage into a ParsedMessage.  If skipLocal is true, it will return nil for
// loopback, local unicast, multicast, and unspecified connections.
// Note that Parse does not populate the Timestamp field, so caller should do so.
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
