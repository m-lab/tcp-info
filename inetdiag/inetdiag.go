// Package inetdiag provides basic structs and utilities for INET_DIAG messaages.
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

import (
	"fmt"
	"log"
	"net"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink/nl"
)

const (
	TCPDIAG_GETSOCK     = 18 // linux/inet_diag.h
	SOCK_DIAG_BY_FAMILY = 20 // linux/sock_diag.h
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
	TCP_ALL = 0xFFF
)

var TcpStatesMap = map[uint8]string{
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

var DiagFamilyMap = map[uint8]string{
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
	IDiagSPort  be16
	IDiagDPort  be16
	IDiagSrc    [4]be32
	IDiagDst    [4]be32
	IDiagIf     uint32
	IDiagCookie [2]uint32
}

// These isZero and isSame functions added for M-Lab
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

func ipv4(original be32) net.IP {
	return net.IPv4(original[0], original[1], original[2], original[3])
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
	return fmt.Sprintf("%s:%d -> %s:%d", id.SrcIP().String(), id.IDiagSPort.Int(), id.DstIP().String(), id.IDiagDPort.Int())
}

type InetDiagReqV2 struct {
	SDiagFamily   uint8
	SDiagProtocol uint8
	IDiagExt      uint8
	Pad           uint8
	IDiagStates   uint32
	Id            InetDiagSockID
}

// SizeofInetDiagReqV2 is the size of the struct.
// TODO should we just make this explicit in the code?
const SizeofInetDiagReqV2 = int(unsafe.Sizeof(InetDiagReqV2{})) // Should be 0x38

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

func (msg *InetDiagMsg) String() string {
	return fmt.Sprintf("%s, %s, %s", DiagFamilyMap[msg.IDiagFamily], TcpStatesMap[msg.IDiagState], msg.Id.String())
}

// Round the length of a netlink route attribute up to align it
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
