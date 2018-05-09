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
	"fmt"
	"log"
	"net"
	"syscall"
	"unsafe"
)

// Constants from linux.
const (
	TCPDIAG_GETSOCK     = 18 // uapi/linux/inet_diag.h
	SOCK_DIAG_BY_FAMILY = 20 // uapi/linux/sock_diag.h

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

// netinet/tcp.h
const (
	_               = iota
	TCP_ESTABLISHED = iota
	TCP_SYN_SENT
	TCP_SYN_RECV
	TCP_FIN_WAIT1
	TCP_FIN_WAIT2
	TCP_TIME_WAIT
	TCP_CLOSE
	TCP_CLOSE_WAIT
	TCP_LAST_ACK
	TCP_LISTEN
	TCP_CLOSING
)

const (
	TCP_ALL_STATES = 0xFFF
)

var tcpStatesMap = map[uint8]string{
	TCP_ESTABLISHED: "established",
	TCP_SYN_SENT:    "syn_sent",
	TCP_SYN_RECV:    "syn_recv",
	TCP_FIN_WAIT1:   "fin_wait1",
	TCP_FIN_WAIT2:   "fin_wait2",
	TCP_TIME_WAIT:   "time_wait",
	TCP_CLOSE:       "close",
	TCP_CLOSE_WAIT:  "close_wait",
	TCP_LAST_ACK:    "last_ack",
	TCP_LISTEN:      "listen",
	TCP_CLOSING:     "closing",
}

var diagFamilyMap = map[uint8]string{
	syscall.AF_INET:  "tcp",
	syscall.AF_INET6: "tcp6",
}

// InetDiagSockID is the binary linux representation of a socket, as in linux/inet_diag.h
// Note that netlink messages use host byte ordering, unless NLA_F_NET_BYTEORDER flag is present.
type InetDiagSockID struct {
	IDiagSPort  uint16
	IDiagDPort  uint16
	IDiagSrc    [16]byte
	IDiagDst    [16]byte
	IDiagIf     uint32
	IDiagCookie [2]uint32 // This cannot be uint64, because of alignment rules.
}

// SrcIP returns a golang net encoding of source address.
func (id *InetDiagSockID) SrcIP() net.IP {
	return ip(id.IDiagSrc)
}

// DstIP returns a golang net encoding of destination address.
func (id *InetDiagSockID) DstIP() net.IP {
	return ip(id.IDiagDst)
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
	return net.IPv4(original[0], original[1], original[2], original[3])
}

func ipv6(original [16]byte) net.IP {
	return original[:]
}

func (id *InetDiagSockID) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d", id.SrcIP().String(), id.IDiagSPort, id.DstIP().String(), id.IDiagDPort)
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

// InetDiagMsg is the linux binary representation of a InetDiag message header, as in linus/inet_diag.h
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
	return fmt.Sprintf("%s, %s, %s", diagFamilyMap[msg.IDiagFamily], tcpStatesMap[msg.IDiagState], msg.ID.String())
}

// rtaAlignOf round the length of a netlink route attribute up to align it
// properly.
func rtaAlignOf(attrlen int) int {
	return (attrlen + syscall.RTA_ALIGNTO - 1) & ^(syscall.RTA_ALIGNTO - 1)
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
