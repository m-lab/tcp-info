// Package tools contains tools to convert netlink messages to protobuf message types.
// It contains structs for raw linux route attribute messages related to tcp-info,
// and code for copying them into protobufs defined in tcpinfo.proto.
package tools

import (
	"bytes"
	"log"
	"syscall"
	"unsafe"

	"github.com/m-lab/tcp-info/inetdiag"
	tcpinfo "github.com/m-lab/tcp-info/nl-proto"

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
	src.Port = uint32(hdr.ID.SPort())
	src.Ip = append(src.Ip, hdr.ID.SrcIP()...)
	dst := tcpinfo.EndPoint{}
	p.SockId.Destination = &dst
	dst.Port = uint32(hdr.ID.DPort())
	dst.Ip = append(dst.Ip, hdr.ID.DstIP()...)
	p.SockId.Interface = hdr.ID.Interface()
	p.SockId.Cookie = hdr.ID.Cookie()
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
	case inetdiag.INET_DIAG_MARK:
		// TODO Already seeing this when run as root, so we should process it.
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
// TODO should these all be unexported?
// TODO Alternatively, should they be in their own package, with exported fields?
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
	// These seem to be elapsed time, so they increase on almost every sample.
	// We can probably use them to get more info about intervals between samples.
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

// MaybeCopy checks whether the src is the full size of the intended struct size.
// If so, it just returns the pointer, otherwise it copies the content to an
// appropriately sized new byte slice, and returns pointer to that.
func MaybeCopy(src []byte, size int) unsafe.Pointer {
	if len(src) < size {
		data := make([]byte, size)
		copy(data, src)
		return unsafe.Pointer(&data[0])
	}
	return unsafe.Pointer(&src[0])
}

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

// ParseSockMemInfo maps the rta Value onto a SockMemInfoProto.
// Since this struct is very simple, it can be mapped directly, instead of using an
// intermediate struct.
func ParseSockMemInfo(rta *syscall.NetlinkRouteAttr) *tcpinfo.SocketMemInfoProto {
	structSize := (int)(unsafe.Sizeof(tcpinfo.SocketMemInfoProto{}))
	return (*tcpinfo.SocketMemInfoProto)(MaybeCopy(rta.Value, structSize))
}

// ParseMemInfo maps the rta Value onto a MemInfoProto.
// Since this struct is very simple, it can be mapped directly, instead of using an
// intermediate struct.
func ParseMemInfo(rta *syscall.NetlinkRouteAttr) *tcpinfo.MemInfoProto {
	structSize := (int)(unsafe.Sizeof(tcpinfo.MemInfoProto{}))
	return (*tcpinfo.MemInfoProto)(MaybeCopy(rta.Value, structSize))
}

// ChangeType indicates why a new record is worthwhile saving.
type ChangeType int

const (
	NoMajorChange        ChangeType = iota
	IDiagStateChange                // The IDiagState changed
	NoTCPInfo                       // There is no TCPInfo attribute
	NewAttribute                    // There is a new attribute
	LostAttribute                   // There is a dropped attribute
	AttributeLength                 // The length of an attribute changed
	StateOrCounterChange            // One of the early fields in DIAG_INFO changed.
	PacketCountChange               // One of the packet/byte/segment counts (or other late field) changed
	Other                           // Some other attribute changed
)

// Compare compares important fields to determine whether significant updates have occurred.
// We ignore a bunch of fields:
//  * The TCPInfo fields matching last_* are rapidly changing, but don't have much significance.
//    Are they elapsed time fields?
//  * The InetDiagMsg.Expires is also rapidly changing in many connections, but also seems
//    unimportant.
//
// Significant updates are reflected in the packet, segment and byte count updates, so we
// generally want to record a snapshot when any of those change.  They are in the latter
// part of the linux struct, following the pmtu field.
//
// The simplest test that seems to tell us what we care about is to look at all the fields
// in the TCPInfo struct related to packets, bytes, and segments.  In addition to the TCPState
// and CAState fields, these are probably adequate, but we also check for new or missing attributes
// and any attribute difference outside of the TCPInfo (INET_DIAG_INFO) attribute.
// TODO:
//  Consider moving this function, together with LinuxTCPInfo, into another package depending only on
//  inetdiag. However, that would require exporting all fields of LinuxTCPInfo, which is not
//  necessary if we keep this here.
func Compare(previous *inetdiag.ParsedMessage, current *inetdiag.ParsedMessage) ChangeType {
	// If the TCP state has changed, that is important!
	if previous.InetDiagMsg.IDiagState != current.InetDiagMsg.IDiagState {
		return IDiagStateChange
	}

	// TODO - should we validate that ID matches?  Otherwise, we shouldn't even be comparing the rest.

	a := previous.Attributes[inetdiag.INET_DIAG_INFO]
	b := current.Attributes[inetdiag.INET_DIAG_INFO]
	if a == nil || b == nil {
		return NoTCPInfo
	}

	// If any of the byte/segment/package counters have changed, that is what we are most
	// interested in.
	if 0 != bytes.Compare(a.Value[PmtuOffset:], b.Value[PmtuOffset:]) {
		return PacketCountChange
	}

	// Check all the earlier fields, too.  Usually these won't change unless the counters above
	// change, but this way we won't miss something subtle.
	if 0 != bytes.Compare(a.Value[:LastDataSentOffset], b.Value[:LastDataSentOffset]) {
		return StateOrCounterChange
	}

	// If any attributes have been added or removed, that is likely significant.
	for tp := range previous.Attributes {
		switch tp {
		case inetdiag.INET_DIAG_INFO:
			// Handled explicitly above.
		default:
			// Detect any change in anything other than INET_DIAG_INFO
			a := previous.Attributes[tp]
			b := current.Attributes[tp]
			if a == nil && b != nil {
				return NewAttribute
			}
			if a != nil && b == nil {
				return LostAttribute
			}
			if a == nil && b == nil {
				continue
			}
			if len(a.Value) != len(b.Value) {
				return AttributeLength
			}
			// All others we want to be identical
			if 0 != bytes.Compare(a.Value, b.Value) {
				return Other
			}
		}
	}

	return NoMajorChange
}
