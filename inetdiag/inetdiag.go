//go:generate ffjson $GOFILE

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
	"syscall"
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
	// TODO - Should check whether this matches the current linux header.
	INET_DIAG_MAX
)

var InetDiagType = map[int32]string{
	INET_DIAG_MEMINFO:   "MemInfo",
	INET_DIAG_INFO:      "TCPInfo",
	INET_DIAG_VEGASINFO: "Vegas",
	INET_DIAG_CONG:      "Congestion",
	INET_DIAG_TOS:       "TOS",
	INET_DIAG_TCLASS:    "TClass",
	INET_DIAG_SKMEMINFO: "SKMemInfo",
	INET_DIAG_SHUTDOWN:  "Shutdown",
	INET_DIAG_DCTCPINFO: "DCTCPInfo",
	INET_DIAG_PROTOCOL:  "Protocol",
	INET_DIAG_SKV6ONLY:  "SKV6Only",
	INET_DIAG_LOCALS:    "Locals",
	INET_DIAG_PEERS:     "Peers",
	INET_DIAG_PAD:       "Pad",
	INET_DIAG_MARK:      "Mark",
	INET_DIAG_BBRINFO:   "BBRInfo",
	INET_DIAG_CLASS_ID:  "ClassID",
	INET_DIAG_MD5SIG:    "MD5Sig",
}

var diagFamilyMap = map[uint8]string{
	syscall.AF_INET:  "tcp",
	syscall.AF_INET6: "tcp6",
}

//	if (tb[INET_DIAG_PROTOCOL])
//		s->raw_prot = rta_getattr_u8(tb[INET_DIAG_PROTOCOL]);
type Protocol uint8

const (
	Protocol_IPPROTO_UNUSED Protocol = 0
	Protocol_IPPROTO_TCP    Protocol = 6
	Protocol_IPPROTO_UDP    Protocol = 17
	Protocol_IPPROTO_DCCP   Protocol = 33
)

var Protocol_name = map[int32]string{
	0:  "IPPROTO_UNUSED",
	6:  "IPPROTO_TCP",
	17: "IPPROTO_UDP",
	33: "IPPROTO_DCCP",
}

var Protocol_value = map[string]int32{
	"IPPROTO_UNUSED": 0,
	"IPPROTO_TCP":    6,
	"IPPROTO_UDP":    17,
	"IPPROTO_DCCP":   33,
}
