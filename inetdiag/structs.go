package inetdiag

/*
There should be a corresponding struct for every element of this enum
defined in uapi/linux/inet_diag.h

	INET_DIAG_MEMINFO
	INET_DIAG_INFO  // This one is in tcp.go
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
*/

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"unsafe"
)

// Constants from linux.
const (
	SOCK_DIAG_BY_FAMILY = 20 // uapi/linux/sock_diag.h
)

const TCPF_ALL = 0xFFF

var (
	// ErrBadPid is used when the PID is mismatched between the netlink socket and the calling process.
	ErrBadPid = errors.New("bad PID, can't listen to NL socket")

	// ErrBadSequence is used when the Netlink response has a bad sequence number.
	ErrBadSequence = errors.New("bad sequence number, can't interpret NetLink response")

	// ErrBadMsgData is used when the NHetlink response has bad or missing data.
	ErrBadMsgData = errors.New("bad message data from netlink message")
)

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

// InetDiagSockID is the binary linux representation of a socket, as in linux/inet_diag.h
// Linux code comments indicate this struct uses the network byte order!!!
type InetDiagSockID struct {
	IDiagSPort [2]byte
	IDiagDPort [2]byte
	IDiagSrc   [16]byte
	IDiagDst   [16]byte
	IDiagIf    [4]byte
	// TODO - change this to [2]uint32 ?
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
	// This is a socket UUID generated within the kernel, and is therefore in host byte order.
	return binary.LittleEndian.Uint64(id.IDiagCookie[:])
}

// TODO should use more net.IP code instead of custom code.
func ip(bytes [16]byte) net.IP {
	if isIpv6(bytes) {
		return ipv6(bytes)
	}
	return ipv4(bytes)
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

// These are related to filters.  We don't currently use filters, so we ignore this type.
type HostCond struct { // inet_diag_hostcond
	Family    uint8  // __u8 family
	PrefixLen uint8  // __u8 prefix_len
	Port      uint16 // int port
	Addr      uint32 // __be32	addr[0];
}
type MarkCond struct { // inet_diag_markcond
	Mark uint32
	Mask uint32
}

// InetDiagMsg is the linux binary representation of a InetDiag message header, as in linux/inet_diag.h
// Note that netlink messages use host byte ordering, unless NLA_F_NET_BYTEORDER flag is present.
// INET_DIAG_INFO
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

// Haven't found a corresponding linux struct, but the message is described
// in https://manpages.debian.org/stretch/manpages/sock_diag.7.en.html
// INET_DIAG_SKMEMINFO
type SocketMemInfo struct {
	RmemAlloc  uint32
	Rcvbuf     uint32
	WmemAlloc  uint32
	Sndbuf     uint32
	FwdAlloc   uint32
	WmemQueued uint32
	Optmem     uint32
	Backlog    uint32
	Drops      uint32
}

// MemInfo corresponds to the linux struct inet_diag_meminfo.
// In is used to decode attribute Type INET_DIAG_MEMINFO
type MemInfo struct {
	Rmem uint32
	Wmem uint32
	Fmem uint32
	Tmem uint32
}

// INET_DIAG_VEGASINFO
type VegasInfo struct {
	Enabled  uint32
	RTTCount uint32
	RTT      uint32
	MinRTT   uint32
}

// INET_DIAG_DCTCPINFO
type DCTCPInfo struct {
	Enabled uint16
	CEState uint16
	Alpha   uint32
	ABEcn   uint32
	ABTot   uint32
}

// BBRInfo corresponds to linux struct tcp_bbr_info.
// Used for decoding attribute Type:INET_DIAG_BBRINFO
type BBRInfo struct {
	Bw         int64  // Max-filtered BW (app throughput) estimate in bytes/second
	MinRtt     uint32 // Min-filtered RTT in uSec
	PacingGain uint32 // Pacing gain shifted left 8 bits
	CwndGain   uint32 // Cwnd gain shifted left 8 bits
}

// LOCALS and PEERS contain an array of sockaddr_storage elements.
/* ss.c parses these elements like this:
static const char *format_host_sa(struct sockaddr_storage *sa)
{
	union {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} *saddr = (void *)sa;

	switch (sa->ss_family) {
	case AF_INET:
		return format_host(AF_INET, 4, &saddr->sin.sin_addr);
	case AF_INET6:
		return format_host(AF_INET6, 16, &saddr->sin6.sin6_addr);
	default:
		return "";
	}
}

	INET_DIAG_LOCALS
if (tb[INET_DIAG_LOCALS]) {
	len = RTA_PAYLOAD(tb[INET_DIAG_LOCALS]);
	sa = RTA_DATA(tb[INET_DIAG_LOCALS]);

	printf("locals:%s", format_host_sa(sa));
	for (sa++, len -= sizeof(*sa); len > 0; sa++, len -= sizeof(*sa))
		printf(",%s", format_host_sa(sa));

}
	INET_DIAG_PEERS
if (tb[INET_DIAG_PEERS]) {
	len = RTA_PAYLOAD(tb[INET_DIAG_PEERS]);
	sa = RTA_DATA(tb[INET_DIAG_PEERS]);

	printf(" peers:%s", format_host_sa(sa));
	for (sa++, len -= sizeof(*sa); len > 0; sa++, len -= sizeof(*sa))
		printf(",%s", format_host_sa(sa));
}
*/

/*

//	INET_DIAG_SKV6ONLY
			v6only = rta_getattr_u8(tb[INET_DIAG_SKV6ONLY]);

//	INET_DIAG_SHUTDOWN
			mask = rta_getattr_u8(tb[INET_DIAG_SHUTDOWN]);




*/

//	INET_DIAG_TOS
//	INET_DIAG_TCLASS
//	INET_DIAG_PAD
//	INET_DIAG_CLASS_ID
//	INET_DIAG_MD5SIG
