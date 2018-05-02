package tcp

// This file contains extensions to the protobuf message types.  It contains structs for raw linux route attribute
// messages related to tcp-info, and code for copying them into protobufs defined in tcp*.proto.

import (
	"log"
	"syscall"
	"unsafe"

	"github.com/m-lab/tcp-info/api"
	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/vishvananda/netlink/nl"
)

var (
	LOG = true
)

// ParseCong returns the congestion algorithm string
func ParseCong(rta *syscall.NetlinkRouteAttr) string {
	return string(rta.Value)
}

// FillFromHeader fills out the InetDiagMsg proto msg with fields from the provided linux InetDiagMsg
func (all *TCPDiagnosticsProto) FillFromHeader(hdr *inetdiag.InetDiagMsg) {
	all.InetDiagMsg = &InetDiagMsgProto{}
	all.InetDiagMsg.Family = InetDiagMsgProto_AddressFamily(hdr.IDiagFamily)
	all.InetDiagMsg.State = TCPState(hdr.IDiagState)
	all.InetDiagMsg.Timer = uint32(hdr.IDiagTimer)
	all.InetDiagMsg.Retrans = uint32(hdr.IDiagRetrans)
	all.InetDiagMsg.SockId = &InetSocketIDProto{}
	src := EndPoint{}
	all.InetDiagMsg.SockId.Source = &src
	src.Port = uint32(hdr.ID.IDiagSPort)
	src.Ip = append(src.Ip, hdr.ID.IDiagSrc[:]...)
	dst := EndPoint{}
	all.InetDiagMsg.SockId.Destination = &dst
	dst.Port = uint32(hdr.ID.IDiagDPort)
	dst.Ip = append(src.Ip, hdr.ID.IDiagDst[:]...)
	all.InetDiagMsg.SockId.Interface = hdr.ID.IDiagIf
	all.InetDiagMsg.SockId.Cookie = uint64(hdr.ID.IDiagCookie[0])<<32 + uint64(hdr.ID.IDiagCookie[1])
	all.InetDiagMsg.Expires = hdr.IDiagExpires
	all.InetDiagMsg.Rqueue = hdr.IDiagRqueue
	all.InetDiagMsg.Wqueue = hdr.IDiagWqueue
	all.InetDiagMsg.Uid = hdr.IDiagUID
	all.InetDiagMsg.Inode = hdr.IDiagInode
}

func (all *TCPDiagnosticsProto) FillFromAttr(rta *syscall.NetlinkRouteAttr) {
	switch rta.Attr.Type {
	case api.INET_DIAG_PROTOCOL:
		if LOG {
			log.Println("Not processing Protocol", rta.Value)
		}
		// Used only for multicast messages. Not expected for our use cases.
		// TODO(gfr) Consider checking for equality, and LOG_FIRST_N.
	case api.INET_DIAG_INFO:
		ldiwr := ParseLinuxDiagInfo(rta)
		all.TcpInfo = &TCPInfoProto{}
		all.TcpInfo.LoadFrom(ldiwr)
	case api.INET_DIAG_CONG:
		all.CongestionAlgorithm = ParseCong(rta)
	case api.INET_DIAG_SHUTDOWN:
		all.Shutdown = &TCPDiagnosticsProto_ShutdownMask{uint32(rta.Value[0])}
	case api.INET_DIAG_MEMINFO:
		all.MemInfo = &MemInfoProto{}
		all.MemInfo.LoadFrom(rta)
	case api.INET_DIAG_SKMEMINFO:
		all.SocketMem = &SocketMemInfoProto{}
		all.SocketMem.LoadFrom(rta)
	case api.INET_DIAG_TOS:
		// TODO
		if LOG {
			log.Println("Not processing TOS", rta.Value)
		}
	case api.INET_DIAG_TCLASS:
		// TODO
		if LOG {
			log.Println("Not processing TCLASS", rta.Value)
		}
	case api.INET_DIAG_BBRINFO:
		if LOG {
			log.Println("Not processing BBRInfo", rta.Value)
		}
		//ParseBBRInfo(rta, proto->mutable_bbr_info());
	case api.INET_DIAG_VEGASINFO:
		if LOG {
			log.Println("Not processing VegasInfo", rta.Value)
		}
		//fprintf(stderr, "Need to do vegas\n");
	case api.INET_DIAG_SKV6ONLY:
		if LOG {
			log.Println("Not processing SK6ONLY", rta.Value)
		}
	case api.INET_DIAG_MARK:
		if LOG {
			log.Println("Not processing MARK", rta.Value)
		}
		// TODO(gfr) Do we need this?
	default:
		log.Printf("Not processing %+v\n", rta)
		// TODO(gfr) - should LOG(WARNING) on missing cases.
	}
}

func (all *TCPDiagnosticsProto) Load(header syscall.NlMsghdr, idm *inetdiag.InetDiagMsg, attrs []*syscall.NetlinkRouteAttr) error {
	all.FillFromHeader(idm)
	for i := range attrs {
		if attrs[i] != nil {
			all.FillFromAttr(attrs[i])
		}
	}

	if LOG {
		log.Printf("nlmsg header: %v Proto: %+v\n", header, all)
	}
	return nil
}

func (all *TCPDiagnosticsProto) LoadFromNLMsg(nlMsg *syscall.NetlinkMessage) error {
	// These are serialized NetlinkMessage
	idm, attrBytes := inetdiag.ParseInetDiagMsg(nlMsg.Data)
	//log.Printf("%+v\n\n", idm)
	all.FillFromHeader(idm)
	attrs, err := nl.ParseRouteAttr(attrBytes)
	if err != nil {
		log.Println(err)
	}
	if LOG {
		//for i := range attrs {
		//	log.Printf("%+v\n", attrs[i].Attr)
		//}
	}
	for i := range attrs {
		all.FillFromAttr(&attrs[i])
	}

	if LOG {
		log.Printf("nlmsg header: %v Proto: %+v\n", nlMsg.Header, all)
	}
	return nil
}

// LinuxTCPInfo is the linux defined structure returned in RouteAttr DIAG_INFO messages.
// TODO - maybe move this to inetdiag module?
type LinuxDiagInfo struct {
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

// Useful offsets
const (
	LastDataSentOffset = unsafe.Offsetof(LinuxDiagInfo{}.lastDataSent)
	PmtuOffset         = unsafe.Offsetof(LinuxDiagInfo{}.pmtu)
)

// ParseLinuxDiagInfo tries to map the rta Value onto a TCPInfo struct.  It may have to copy the
// bytes.
func ParseLinuxDiagInfo(rta *syscall.NetlinkRouteAttr) *LinuxDiagInfo {
	structSize := (int)(unsafe.Sizeof(LinuxDiagInfo{}))
	data := rta.Value
	//log.Println(len(rta.Value), "vs", structSize)
	if len(rta.Value) < structSize {
		// log.Println(len(rta.Value), "vs", structSize)
		data = make([]byte, structSize)
		copy(data, rta.Value)
	}
	return (*LinuxDiagInfo)(unsafe.Pointer(&data[0]))
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

// ParseSockMemInfo tries to map the rta Value onto a TCPInfo struct.  It may have to copy the
// bytes.
func ParseSockMemInfo(rta *syscall.NetlinkRouteAttr) *SocketMemInfoProto {
	if len(rta.Value) != 36 {
		log.Println(len(rta.Value))
		return nil
	}
	return (*SocketMemInfoProto)(unsafe.Pointer(&rta.Value[0]))
}

func (p *SocketMemInfoProto) LoadFrom(rta *syscall.NetlinkRouteAttr) {
	memInfo := ParseSockMemInfo(rta)
	if memInfo != nil {
		// Copy
		*p = *memInfo
	}
}

// ParseSockMemInfo tries to map the rta Value onto a TCPInfo struct.  It may have to copy the
// bytes.
func ParseMemInfo(rta *syscall.NetlinkRouteAttr) *MemInfoProto {
	if len(rta.Value) != 16 {
		log.Println(len(rta.Value))
		return nil
	}
	return (*MemInfoProto)(unsafe.Pointer(&rta.Value[0]))
}

func (p *MemInfoProto) LoadFrom(rta *syscall.NetlinkRouteAttr) {
	memInfo := ParseMemInfo(rta)
	if memInfo != nil {
		// Copy
		*p = *memInfo
	}
}

func (p *TCPInfoProto) LoadFrom(diag *LinuxDiagInfo) {
	// TODO state ???
	p.State = TCPState(diag.state)

	p.CaState = uint32(diag.caState)
	p.Retransmits = uint32(diag.retransmits)
	p.Probes = uint32(diag.probes)
	p.Backoff = uint32(diag.backoff)
	opts := diag.options
	p.Options = uint32(opts)
	p.TsOpt = opts&0x01 > 0
	p.SackOpt = opts&0x02 > 0
	p.WscaleOpt = opts&0x04 > 0
	p.EcnOpt = opts&0x08 > 0
	p.EcnseenOpt = opts&0x10 > 0
	p.FastopenOpt = opts&0x20 > 0

	p.RcvWscale = uint32(diag.wscale & 0x0F)
	p.SndWscale = uint32(diag.wscale >> 4)
	p.DeliveryRateAppLimited = diag.appLimited > 0

	p.Rto = diag.rto
	p.Ato = diag.ato
	p.SndMss = diag.sndMss
	p.RcvMss = diag.rcvMss

	p.Unacked = diag.unacked
	p.Sacked = diag.sacked
	p.Lost = diag.lost
	p.Retrans = diag.retrans
	p.Fackets = diag.fackets
	p.LastDataSent = diag.lastDataSent
	p.LastAckSent = diag.lastAckSent
	p.LastDataRecv = diag.lastDataRecv
	p.LastAckRecv = diag.lastAckRecv

	p.Pmtu = diag.pmtu
	if diag.rcvSsThresh < 0xFFFF {
		p.RcvSsthresh = diag.rcvSsThresh
	}
	p.Rtt = diag.rtt
	p.Rttvar = diag.rttvar
	p.SndSsthresh = diag.sndSsThresh
	p.SndCwnd = diag.sndCwnd
	p.Advmss = diag.advmss
	p.Reordering = diag.reordering

	p.RcvRtt = diag.rcvRtt
	p.RcvSpace = diag.rcvSpace
	p.TotalRetrans = diag.totalRetrans

	p.PacingRate = diag.pacingRate
	p.MaxPacingRate = diag.maxPacingRate
	p.BytesAcked = diag.bytesAcked
	p.BytesReceived = diag.bytesReceived

	p.SegsOut = diag.segsOut
	p.SegsIn = diag.segsIn

	p.NotsentBytes = diag.notsentBytes
	p.MinRtt = diag.minRtt
	p.DataSegsIn = diag.dataSegsIn
	p.DataSegsOut = diag.dataSegsOut

	p.DeliveryRate = diag.deliveryRate
}
