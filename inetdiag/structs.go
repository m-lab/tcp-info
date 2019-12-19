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
	"log"
	"net"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/m-lab/go/anonymize"
)

// Constants from linux.
const (
	SOCK_DIAG_BY_FAMILY = 20 // uapi/linux/sock_diag.h
)

var (
	// ErrBadPid is used when the PID is mismatched between the netlink socket and the calling process.
	ErrBadPid = errors.New("bad PID, can't listen to NL socket")

	// ErrBadSequence is used when the Netlink response has a bad sequence number.
	ErrBadSequence = errors.New("bad sequence number, can't interpret NetLink response")

	// ErrBadMsgData is used when the NHetlink response has bad or missing data.
	ErrBadMsgData = errors.New("bad message data from netlink message")
)

// ReqV2 is the Netlink request struct, as in linux/inet_diag.h
// Note that netlink messages use host byte ordering, unless NLA_F_NET_BYTEORDER flag is present.
type ReqV2 struct {
	SDiagFamily   uint8
	SDiagProtocol uint8
	IDiagExt      uint8
	Pad           uint8
	IDiagStates   uint32
	ID            LinuxSockID
}

// SizeofReqV2 is the size of the struct.
// TODO should we just make this explicit in the code?
const SizeofReqV2 = int(unsafe.Sizeof(ReqV2{})) // Should be 0x38

// Serialize is provided for json serialization?
// TODO - should use binary functions instead?
func (req *ReqV2) Serialize() []byte {
	return (*(*[SizeofReqV2]byte)(unsafe.Pointer(req)))[:]
}

// Len is provided for json serialization?
func (req *ReqV2) Len() int {
	return SizeofReqV2
}

// NewReqV2 creates a new request.
func NewReqV2(family, protocol uint8, states uint32) *ReqV2 {
	return &ReqV2{
		SDiagFamily:   family,
		SDiagProtocol: protocol,
		IDiagStates:   states,
	}
}

// Types for LinuxSockID fields.
type cookieType [8]byte

// TODO - remove all these.
func (c *cookieType) MarshalCSV() (string, error) {
	value := binary.LittleEndian.Uint64(c[:])
	return fmt.Sprintf("%X", value), nil
}

type ipType [16]byte

// MarshalCSV marshals ipType to CSV
func (ipAddr *ipType) MarshalCSV() (string, error) {
	netIP := ip(*ipAddr)
	return netIP.String(), nil
}

// Port encodes a LinuxSockID Port
type Port [2]byte

// MarshalCSV marshals a Port to CSV
func (p *Port) MarshalCSV() (string, error) {
	value := binary.BigEndian.Uint16(p[:])
	return fmt.Sprintf("%d", value), nil
}

// Interface encodes the LinuxSockID Interface field.
type netIF [4]byte

// MarshalCSV marshals Interface to CSV
func (nif *netIF) MarshalCSV() (string, error) {
	value := binary.BigEndian.Uint32(nif[:])
	return fmt.Sprintf("%d", value), nil
}

// LinuxSockID is the binary linux representation of a socket, as in linux/inet_diag.h
// Linux code comments indicate this struct uses the network byte order!!!
// All fields are ignored for bigquery, and handled in code.
// TODO make this unexported
type LinuxSockID struct {
	IDiagSPort  Port       `csv:"IDM.SockID.SPort" bigquery:"-"`
	IDiagDPort  Port       `csv:"IDM.SockID.DPort" bigquery:"-"`
	IDiagSrc    ipType     `csv:"IDM.SockID.Src" bigquery:"-"`
	IDiagDst    ipType     `csv:"IDM.SockID.Dst" bigquery:"-"`
	IDiagIf     netIF      `csv:"IDM.SockID.Interface" bigquery:"-"`
	IDiagCookie cookieType `csv:"IDM.SockID.Cookie" bigquery:"-"`
}

// SockID is the natural golang struct equivalent of LinuxSockID
type SockID struct {
	SPort     uint16
	DPort     uint16
	SrcIP     string
	DstIP     string
	Interface uint32
	Cookie    int64 // Actually a uint64, but using int64 for compatibility with BigQuery
}

// CookieUint64 returns the original uint64 cookie value.
func (sid *SockID) CookieUint64() uint64 {
	return *(*uint64)(unsafe.Pointer(&sid.Cookie))
}

// GetSockID extracts the SockID from the LinuxSockID.
func (id *LinuxSockID) GetSockID() SockID {
	sid := SockID{
		SrcIP:     id.SrcIP().String(),
		SPort:     id.SPort(),
		DstIP:     id.DstIP().String(),
		DPort:     id.DPort(),
		Interface: id.Interface(),
		Cookie:    int64(id.Cookie()),
	}
	return sid
}

// Interface returns the interface number.
func (id *LinuxSockID) Interface() uint32 {
	return binary.BigEndian.Uint32(id.IDiagIf[:])
}

// SrcIP returns a golang net encoding of source address.
func (id *LinuxSockID) SrcIP() net.IP {
	return ip(id.IDiagSrc)
}

// DstIP returns a golang net encoding of destination address.
func (id *LinuxSockID) DstIP() net.IP {
	return ip(id.IDiagDst)
}

// SPort returns the host byte ordered port.
// In general, Netlink is supposed to use host byte order, but this seems to be an exception.
// Perhaps Netlink is reading a tcp stack structure that holds the port in network byte order.
func (id *LinuxSockID) SPort() uint16 {
	return binary.BigEndian.Uint16(id.IDiagSPort[:])
}

// DPort returns the host byte ordered port.
// In general, Netlink is supposed to use host byte order, but this seems to be an exception.
// Perhaps Netlink is reading a tcp stack structure that holds the port in network byte order.
func (id *LinuxSockID) DPort() uint16 {
	return binary.BigEndian.Uint16(id.IDiagDPort[:])
}

// Cookie returns the LinuxSockID's 64 bit unsigned cookie.
func (id *LinuxSockID) Cookie() uint64 {
	// This is a socket UUID generated within the kernel, and is therefore in host byte order.
	return binary.LittleEndian.Uint64(id.IDiagCookie[:])
}

// TODO should use more net.IP code instead of custom code.
// TODO: reconcile this encoding of v4-in-v6 with the encoding used in https://golang.org/src/net/ip.go?s=1216:1245#L35
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

// HostCond is related to filters.  We don't currently use filters, so we don't actually use this type.
type HostCond struct { // inet_diag_hostcond
	Family    uint8  // __u8 family
	PrefixLen uint8  // __u8 prefix_len
	Port      uint16 // int port
	Addr      uint32 // __be32	addr[0];
}

// MarkCond is related to filters.  We don't currently use filters, so we don't actually use this type.
type MarkCond struct { // inet_diag_markcond
	Mark uint32
	Mask uint32
}

// InetDiagMsg is the linux binary representation of a InetDiag message header, as in linux/inet_diag.h
// Note that netlink messages use host byte ordering, unless NLA_F_NET_BYTEORDER flag is present.
type InetDiagMsg struct {
	IDiagFamily  uint8 `csv:"IDM.Family"`
	IDiagState   uint8 `csv:"IDM.State"`
	IDiagTimer   uint8 `csv:"IDM.Timer"`
	IDiagRetrans uint8 `csv:"IDM.Retrans"`
	// The ID is handled separately for both CSV and BigQuery, so they are tagged with "-"
	ID           LinuxSockID `csv:"-" bigquery:"-"`
	IDiagExpires uint32      `csv:"IDM.Expires"`
	IDiagRqueue  uint32      `csv:"IDM.Rqueue"`
	IDiagWqueue  uint32      `csv:"IDM.Wqueue"`
	IDiagUID     uint32      `csv:"IDM.UID"`
	IDiagInode   uint32      `csv:"IDM.Inode"`
}

const (
	// This previously came from syscall, but explicit here to work on Darwin.
	RTA_ALIGNTO = 4
)

// rtaAlignOf rounds the length of a netlink route attribute up to align it properly.
func rtaAlignOf(attrlen int) int {
	return (attrlen + RTA_ALIGNTO - 1) & ^(RTA_ALIGNTO - 1)
}

// RawInetDiagMsg holds the []byte representation of an InetDiagMsg
type RawInetDiagMsg []byte

func SplitInetDiagMsg(data []byte) (RawInetDiagMsg, []byte) {
	// TODO - why using rtaAlign on InetDiagMsg ???
	align := rtaAlignOf(int(unsafe.Sizeof(InetDiagMsg{})))
	if len(data) < align {
		log.Println("Wrong length", len(data), "<", align)
		_, file, line, _ := runtime.Caller(2)
		log.Println(file, line, data)
		return nil, nil
	}
	return RawInetDiagMsg(data[:align]), data[align:]
}

var ErrParseFailed = errors.New("Unable to parse InetDiagMsg")

// Parse returns the InetDiagMsg itself
// Modified from original to also return attribute data array.
func (raw RawInetDiagMsg) Parse() (*InetDiagMsg, error) {
	// TODO - why using rtaAlign on InetDiagMsg ???

	align := rtaAlignOf(int(unsafe.Sizeof(InetDiagMsg{})))
	if len(raw) < align {
		return nil, ErrParseFailed
	}
	return (*InetDiagMsg)(unsafe.Pointer(&raw[0])), nil
}

// Anonymize applies the given IPAnonymizer to the src and dest IP addresses
// embedded in the RawInetDiagMsg. Anonymization is applied in-place.
func (raw RawInetDiagMsg) Anonymize(anon anonymize.IPAnonymizer) error {
	msg, err := raw.Parse()
	if err != nil {
		return err
	}
	switch msg.IDiagFamily {
	case syscall.AF_INET6:
		anon.IP(net.IP(msg.ID.IDiagSrc[:]))
		anon.IP(net.IP(msg.ID.IDiagDst[:]))
	case syscall.AF_INET:
		anon.IP(net.IP(msg.ID.IDiagSrc[:4]))
		anon.IP(net.IP(msg.ID.IDiagDst[:4]))
	default:
		panic(fmt.Sprintf("unknown address family: %d", msg.IDiagFamily))
	}
	return nil
}

// SocketMemInfo implements the struct associated with INET_DIAG_SKMEMINFO
// Haven't found a corresponding linux struct, but the message is described
// in https://manpages.debian.org/stretch/manpages/sock_diag.7.en.html
type SocketMemInfo struct {
	RmemAlloc  uint32 `csv:"SKMemInfo.RmemAlloc"`
	Rcvbuf     uint32 `csv:"SKMemInfo.Rcvbuf"`
	WmemAlloc  uint32 `csv:"SKMemInfo.WmemAlloc"`
	Sndbuf     uint32 `csv:"SKMemInfo.Sndbug"`
	FwdAlloc   uint32 `csv:"SKMemInfo.FwdAlloc"`
	WmemQueued uint32 `csv:"SKMemInfo.WmemQueued"`
	Optmem     uint32 `csv:"SKMemInfo.Optmem"`
	Backlog    uint32 `csv:"SKMemInfo.Backlog"`
	Drops      uint32 `csv:"SKMemInfo.Drops"`
}

// MemInfo implements the struct associated with INET_DIAG_MEMINFO, corresponding with
// linux struct inet_diag_meminfo in uapi/linux/inet_diag.h.
type MemInfo struct {
	Rmem uint32 `csv:"MemInfo.Rmem"`
	Wmem uint32 `csv:"MemInfo.Wmem"`
	Fmem uint32 `csv:"MemInfo.Fmem"`
	Tmem uint32 `csv:"MemInfo.Tmem"`
}

// VegasInfo implements the struct associated with INET_DIAG_VEGASINFO, corresponding with
// linux struct tcpvegas_info in uapi/linux/inet_diag.h.
type VegasInfo struct {
	Enabled  uint32 `csv:"Vegas.Enabled"`
	RTTCount uint32 `csv:"Vegas.RTTCount"`
	RTT      uint32 `csv:"Vegas.RTT"`
	MinRTT   uint32 `csv:"Vegas.MinRTT"`
}

// DCTCPInfo implements the struct associated with INET_DIAG_DCTCPINFO attribute, corresponding with
// linux struct tcp_dctcp_info in uapi/linux/inet_diag.h.
type DCTCPInfo struct {
	Enabled uint16 `csv:"DCTCP.Enabled"`
	CEState uint16 `csv:"DCTCP.CEState"`
	Alpha   uint32 `csv:"DCTCP.Alpha"`
	ABEcn   uint32 `csv:"DCTCP.ABEcn"`
	ABTot   uint32 `csv:"DCTCP.ABTot"`
}

// BBRInfo implements the struct associated with INET_DIAG_BBRINFO attribute, corresponding with
// linux struct tcp_bbr_info in uapi/linux/inet_diag.h.
type BBRInfo struct {
	BW         int64  `csv:"BBR.BW"`         // Max-filtered BW (app throughput) estimate in bytes/second
	MinRTT     uint32 `csv:"BBR.MinRTT"`     // Min-filtered RTT in uSec
	PacingGain uint32 `csv:"BBR.PacingGain"` // Pacing gain shifted left 8 bits
	CwndGain   uint32 `csv:"BBR.CwndGain"`   // Cwnd gain shifted left 8 bits
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
