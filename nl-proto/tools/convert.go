// Package tools contains tools to convert netlink messages to protobuf message types.
//  It contains structs for raw linux route attribute
// messages related to tcp-info, and code for copying them into protobufs defined in tcp*.proto.
package tools

import (
	"log"
	"syscall"
	"unsafe"

	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/tcp-info/nl-proto"

	// Hack to force loading library, which is currently used only in nested test.
	_ "github.com/vishvananda/netlink/nl"
)

// ParseCong returns the congestion algorithm string
func ParseCong(rta *syscall.NetlinkRouteAttr) string {
	return string(rta.Value[:len(rta.Value)-1])
}

// HeaderToProto creates an InetDiagMsgProto from the InetDiagMsg message.
func HeaderToProto(hdr *inetdiag.InetDiagMsg) *tcpinfo.InetDiagMsgProto {
	p := tcpinfo.InetDiagMsgProto{}
	p.Family = tcpinfo.InetDiagMsgProto_AddressFamily(hdr.IDiagFamily)
	p.State = tcpinfo.TCPState(hdr.IDiagState)
	p.Timer = uint32(hdr.IDiagTimer)
	p.Retrans = uint32(hdr.IDiagRetrans)
	p.SockId = &tcpinfo.InetSocketIDProto{}
	src := tcpinfo.EndPoint{}
	p.SockId.Source = &src
	src.Port = uint32(hdr.ID.IDiagSPort)
	src.Ip = append(src.Ip, hdr.ID.SrcIP()...)
	dst := tcpinfo.EndPoint{}
	p.SockId.Destination = &dst
	dst.Port = uint32(hdr.ID.IDiagDPort)
	dst.Ip = append(dst.Ip, hdr.ID.DstIP()...)
	p.SockId.Interface = hdr.ID.IDiagIf
	p.SockId.Cookie = uint64(hdr.ID.IDiagCookie[0])<<32 + uint64(hdr.ID.IDiagCookie[1])
	p.Expires = hdr.IDiagExpires
	p.Rqueue = hdr.IDiagRqueue
	p.Wqueue = hdr.IDiagWqueue
	p.Uid = hdr.IDiagUID
	p.Inode = hdr.IDiagInode

	return &p
}

// AttrToField fills the appropriate proto subfield from a route attribute.
func AttrToField(all *tcpinfo.TCPDiagnosticsProto, rta *syscall.NetlinkRouteAttr) {
	switch rta.Attr.Type {
	case inetdiag.INET_DIAG_INFO:
		ldiwr := ParseLinuxTCPInfo(rta)
		all.TcpInfo = ldiwr.ToProto()
	case inetdiag.INET_DIAG_CONG:
		all.CongestionAlgorithm = ParseCong(rta)
	case inetdiag.INET_DIAG_SHUTDOWN:
		all.Shutdown = &tcpinfo.TCPDiagnosticsProto_ShutdownMask{ShutdownMask: uint32(rta.Value[0])}
	case inetdiag.INET_DIAG_MEMINFO:
		memInfo := ParseMemInfo(rta)
		if memInfo != nil {
			all.MemInfo = &tcpinfo.MemInfoProto{}
			*all.MemInfo = *memInfo // Copy, to avoid references the attribute
		}
	case inetdiag.INET_DIAG_SKMEMINFO:
		memInfo := ParseSockMemInfo(rta)
		if memInfo != nil {
			all.SocketMem = &tcpinfo.SocketMemInfoProto{}
			*all.SocketMem = *memInfo // Copy, to avoid references the attribute
		}
	case inetdiag.INET_DIAG_TOS:
		// TODO - already seeing these.  Issue #10
	case inetdiag.INET_DIAG_TCLASS:
		// TODO - already seeing these.  Issue #10

	// We are not seeing these so far.  Should implement BBRINFO soon though.
	// TODO case inetdiag.INET_DIAG_BBRINFO:
	// TODO case inetdiag.INET_DIAG_VEGASINFO:
	// TODO case inetdiag.INET_DIAG_SKV6ONLY:
	// TODO case inetdiag.INET_DIAG_MARK:
	// TODO case inetdiag.INET_DIAG_PROTOCOL:
	//   Used only for multicast messages. Not expected for our use cases.
	default:
		log.Printf("Not processing %+v\n", rta)
		// TODO(gfr) - should LOG(WARNING) on missing cases.
	}
}

// CreateProto creates a fully populated TCPDiagnosticsProto from the parsed elements of a type 20 netlink message.
// This assumes the netlink message is type 20, and behavior is undefined if it is not.
func CreateProto(header syscall.NlMsghdr, idm *inetdiag.InetDiagMsg, attrs []*syscall.NetlinkRouteAttr) *tcpinfo.TCPDiagnosticsProto {
	all := tcpinfo.TCPDiagnosticsProto{}
	all.InetDiagMsg = HeaderToProto(idm)
	for i := range attrs {
		if attrs[i] != nil {
			AttrToField(&all, attrs[i])
		}
	}

	return &all
}

// LinuxTCPInfo is the linux defined structure returned in RouteAttr DIAG_INFO messages.
// It corresponds to the struct tcp_info in include/uapi/linux/tcp.h
// TODO - maybe move this to inetdiag module?
type LinuxTCPInfo struct {
	state       uint8
	caState     uint8
	retransmits uint8
	probes      uint8
	backoff     uint8
	options     uint8
	wscale      uint8 //snd_wscale : 4, tcpi_rcv_wscale : 4;
	appLimited  uint8 //delivery_rate_app_limited:1;

	rto    uint32 // offset 8
	ato    uint32
	sndMss uint32
	rcvMss uint32

	unacked uint32 // offset 24
	sacked  uint32
	lost    uint32
	retrans uint32
	fackets uint32

	/* Times. */
	lastDataSent uint32 // offset 44
	lastAckSent  uint32 /* Not remembered, sorry. */ // offset 48
	lastDataRecv uint32 // offset 52
	lastAckRecv  uint32 // offset 56

	/* Metrics. */
	pmtu        uint32
	rcvSsThresh uint32
	rtt         uint32
	rttvar      uint32
	sndSsThresh uint32
	sndCwnd     uint32
	advmss      uint32
	reordering  uint32

	rcvRtt   uint32
	rcvSpace uint32

	totalRetrans uint32

	pacingRate    int64  // This is often -1, so better for it to be signed
	maxPacingRate int64  // This is often -1, so better to be signed.
	bytesAcked    uint64 /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
	bytesReceived uint64 /* RFC4898 tcpEStatsAppHCThruOctetsReceived */
	segsOut       uint32 /* RFC4898 tcpEStatsPerfSegsOut */
	segsIn        uint32 /* RFC4898 tcpEStatsPerfSegsIn */

	notsentBytes uint32
	minRtt       uint32
	dataSegsIn   uint32 /* RFC4898 tcpEStatsDataSegsIn */
	dataSegsOut  uint32 /* RFC4898 tcpEStatsDataSegsOut */

	deliveryRate uint64

	// TODO - for speed, maybe use a separate struct if these aren't provided by kernel?
	// This would avoid all the allocation and copying.
	// Alternatively, at least reuse the byte slices?
	busyTime      uint64 /* Time (usec) busy sending data */
	rwndLimited   uint64 /* Time (usec) limited by receive window */
	sndbufLimited uint64 /* Time (usec) limited by send buffer */
}

// ToProto converts a LinuxTCPInfo struct to a TCPInfoProto
func (tcp *LinuxTCPInfo) ToProto() *tcpinfo.TCPInfoProto {
	var p tcpinfo.TCPInfoProto
	p.State = tcpinfo.TCPState(tcp.state)

	p.CaState = uint32(tcp.caState)
	p.Retransmits = uint32(tcp.retransmits)
	p.Probes = uint32(tcp.probes)
	p.Backoff = uint32(tcp.backoff)
	opts := tcp.options
	p.Options = uint32(opts)
	p.TsOpt = opts&0x01 > 0
	p.SackOpt = opts&0x02 > 0
	p.WscaleOpt = opts&0x04 > 0
	p.EcnOpt = opts&0x08 > 0
	p.EcnseenOpt = opts&0x10 > 0
	p.FastopenOpt = opts&0x20 > 0

	p.RcvWscale = uint32(tcp.wscale & 0x0F)
	p.SndWscale = uint32(tcp.wscale >> 4)
	p.DeliveryRateAppLimited = tcp.appLimited > 0

	p.Rto = tcp.rto
	p.Ato = tcp.ato
	p.SndMss = tcp.sndMss
	p.RcvMss = tcp.rcvMss

	p.Unacked = tcp.unacked
	p.Sacked = tcp.sacked
	p.Lost = tcp.lost
	p.Retrans = tcp.retrans
	p.Fackets = tcp.fackets
	p.LastDataSent = tcp.lastDataSent
	p.LastAckSent = tcp.lastAckSent
	p.LastDataRecv = tcp.lastDataRecv
	p.LastAckRecv = tcp.lastAckRecv

	p.Pmtu = tcp.pmtu
	if tcp.rcvSsThresh < 0xFFFF {
		p.RcvSsthresh = tcp.rcvSsThresh
	}
	p.Rtt = tcp.rtt
	p.Rttvar = tcp.rttvar
	p.SndSsthresh = tcp.sndSsThresh
	p.SndCwnd = tcp.sndCwnd
	p.Advmss = tcp.advmss
	p.Reordering = tcp.reordering

	p.RcvRtt = tcp.rcvRtt
	p.RcvSpace = tcp.rcvSpace
	p.TotalRetrans = tcp.totalRetrans

	p.PacingRate = tcp.pacingRate
	p.MaxPacingRate = tcp.maxPacingRate
	p.BytesAcked = tcp.bytesAcked
	p.BytesReceived = tcp.bytesReceived

	p.SegsOut = tcp.segsOut
	p.SegsIn = tcp.segsIn

	p.NotsentBytes = tcp.notsentBytes
	p.MinRtt = tcp.minRtt
	p.DataSegsIn = tcp.dataSegsIn
	p.DataSegsOut = tcp.dataSegsOut

	p.DeliveryRate = tcp.deliveryRate

	return &p
}

// Useful offsets
const (
	LastDataSentOffset = unsafe.Offsetof(LinuxTCPInfo{}.lastDataSent)
	PmtuOffset         = unsafe.Offsetof(LinuxTCPInfo{}.pmtu)
)

// ParseLinuxTCPInfo maps the rta Value onto a TCPInfo struct.  It may have to copy the
// bytes.
func ParseLinuxTCPInfo(rta *syscall.NetlinkRouteAttr) *LinuxTCPInfo {
	structSize := (int)(unsafe.Sizeof(LinuxTCPInfo{}))
	data := rta.Value
	//log.Println(len(rta.Value), "vs", structSize)
	if len(rta.Value) < structSize {
		// log.Println(len(rta.Value), "vs", structSize)
		data = make([]byte, structSize)
		copy(data, rta.Value)
	}
	return (*LinuxTCPInfo)(unsafe.Pointer(&data[0]))
}

// SockMemInfo contains report of socket memory.
type SockMemInfo struct {
	RMemAlloc  uint32
	RcvBuf     uint32
	WMemAlloc  uint32
	SendBuf    uint32
	FwdAlloc   uint32
	WMemQueued uint32
	OptMem     uint32
	Backlog    uint32
	Drops      uint32
	// TMem       uint32  // Only in MemInfo, not SockMemInfo
}

// ParseSockMemInfo maps the rta Value onto a TCPInfo struct.
func ParseSockMemInfo(rta *syscall.NetlinkRouteAttr) *tcpinfo.SocketMemInfoProto {
	if len(rta.Value) != 36 {
		log.Println(len(rta.Value))
		return nil
	}
	return (*tcpinfo.SocketMemInfoProto)(unsafe.Pointer(&rta.Value[0]))
}

// ParseMemInfo maps the rta Value onto a MemInfo struct.
func ParseMemInfo(rta *syscall.NetlinkRouteAttr) *tcpinfo.MemInfoProto {
	if len(rta.Value) != 16 {
		log.Println(len(rta.Value))
		return nil
	}
	return (*tcpinfo.MemInfoProto)(unsafe.Pointer(&rta.Value[0]))
}
