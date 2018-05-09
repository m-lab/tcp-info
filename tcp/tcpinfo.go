package tcp

import (
	"log"
	"syscall"
	"unsafe"

	"github.com/m-lab/tcp-info/other"
	"github.com/m-lab/tcp-info/other/api"
	"github.com/vishvananda/netlink/nl"
)

const (
	LOG = false
)

// ParseCong returns the congestion algorithm string
func ParseCong(rta *syscall.NetlinkRouteAttr) string {
	return string(rta.Value)
}

func (all *TCPDiagnosticsProto) FillFromHeader(hdr *other.InetDiagMsg) {
	all.InetDiagMsg = &InetDiagMsgProto{}
	all.InetDiagMsg.Family = InetDiagMsgProto_AddressFamily(hdr.IDiagFamily)
	all.InetDiagMsg.State = TCPState(hdr.IDiagState)
	all.InetDiagMsg.Timer = uint32(hdr.IDiagTimer)
	all.InetDiagMsg.Retrans = uint32(hdr.IDiagRetrans)
	all.InetDiagMsg.SockId = &InetSocketIDProto{}
	src := EndPoint{}
	all.InetDiagMsg.SockId.Source = &src
	src.Port = uint32(hdr.Id.IDiagSPort.Int())
	for _, be := range hdr.Id.IDiagSrc {
		src.Ip = append(src.Ip, be[0], be[1], be[2], be[3])
	}
	dst := EndPoint{}
	all.InetDiagMsg.SockId.Destination = &dst
	dst.Port = uint32(hdr.Id.IDiagDPort.Int())
	for _, be := range hdr.Id.IDiagDst {
		dst.Ip = append(dst.Ip, be[0], be[1], be[2], be[3])
	}
	all.InetDiagMsg.SockId.Interface = hdr.Id.IDiagIf
	all.InetDiagMsg.SockId.Cookie = uint64(hdr.Id.IDiagCookie[0])<<32 + uint64(hdr.Id.IDiagCookie[1])
	all.InetDiagMsg.Expires = hdr.IDiagExpires
	all.InetDiagMsg.Rqueue = hdr.IDiagRqueue
	all.InetDiagMsg.Wqueue = hdr.IDiagWqueue
	all.InetDiagMsg.Uid = hdr.IDiagUid
	all.InetDiagMsg.Inode = hdr.IDiagInode
}

func (all *TCPDiagnosticsProto) FillFromAttr(rta *syscall.NetlinkRouteAttr) {
	switch rta.Attr.Type {
	case api.INET_DIAG_PROTOCOL:
		if LOG {
			log.Println("Protocol", rta.Value)
		}
		// Used only for multicast messages. Not expected for our use cases.
		// TODO(gfr) Consider checking for equality, and LOG_FIRST_N.
	case api.INET_DIAG_INFO:
		ldiwr := ParseLinuxDiagInfo(rta)
		all.TcpInfo = &TCPInfoProto{}
		all.TcpInfo.LoadFrom(ldiwr.Info)
	case api.INET_DIAG_CONG:
		all.CongestionAlgorithm = ParseCong(rta)
	case api.INET_DIAG_SHUTDOWN:
		// TODO
		if LOG {
			log.Printf("SHUTDOWN %2x\n", rta.Value[0])
		}
	case api.INET_DIAG_MEMINFO:
		all.MemInfo = &MemInfoProto{}
		all.MemInfo.LoadFrom(rta)
	case api.INET_DIAG_SKMEMINFO:
		all.SocketMem = &SocketMemInfoProto{}
		all.SocketMem.LoadFrom(rta)
	case api.INET_DIAG_BBRINFO:
		if LOG {
			log.Println("BBRInfo", rta.Value)
		}
		//ParseBBRInfo(rta, proto->mutable_bbr_info());
	case api.INET_DIAG_VEGASINFO:
		if LOG {
			log.Println("VegasInfo", rta.Value)
		}
		//fprintf(stderr, "Need to do vegas\n");
	case api.INET_DIAG_SKV6ONLY:
		if LOG {
			log.Println("SK6", rta.Value)
		}
		// TODO(gfr) Do we need this?
	default:
		// TODO(gfr) - should LOG(WARNING) on missing cases.
	}
}

func (all *TCPDiagnosticsProto) LoadFromAttr(nlMsg *syscall.NetlinkMessage) error {
	// These are serialized NetlinkMessage
	idm := other.ParseInetDiagMsg(nlMsg.Data)
	//log.Printf("%+v\n\n", idm)
	all.FillFromHeader(&idm.Header)
	attrs, err := nl.ParseRouteAttr(idm.Data)
	if err != nil {
		log.Println(err)
	}
	for i := range attrs {
		all.FillFromAttr(&attrs[i])
	}

	if LOG {
		log.Printf("All %+v\n", all)
	}
	return nil
}

// LinuxTCPInfo is the linux defined structure returned in RouteAttr DIAG_INFO messages.
type LinuxDiagInfo struct {
	state       uint8
	caState     uint8
	retransmits uint8
	probes      uint8
	backoff     uint8
	options     uint8
	wscale      uint8 //snd_wscale : 4, tcpi_rcv_wscale : 4;
	appLimited  uint8 //delivery_rate_app_limited:1;

	rto    uint32
	ato    uint32
	sndMss uint32
	rcvMss uint32

	unacked uint32
	sacked  uint32
	lost    uint32
	retrans uint32
	fackets uint32

	/* Times. */
	lastDataSent uint32
	lastAckSent  uint32 /* Not remembered, sorry. */
	lastDataRecv uint32
	lastAckRecv  uint32

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

// We will often want to map the buffer returned from netlink as a TCPInfo struct.  But
// we also need to maintain the reference.

// TCPInfoWithRef holds a TCPInfo pointer and a pointer to the underlying slice.
type LinuxDiagInfoWithRef struct {
	Info *LinuxDiagInfo // Warning - do not copy this pointer without the ref.
	ref  []byte         // Reference to the underlying slice.
}

// ParseLinuxDiagInfo tries to map the rta Value onto a TCPInfo struct.  It may have to copy the
// bytes.
func ParseLinuxDiagInfo(rta *syscall.NetlinkRouteAttr) LinuxDiagInfoWithRef {
	structSize := (int)(unsafe.Sizeof(LinuxDiagInfo{}))
	data := rta.Value
	if len(rta.Value) < structSize {
		data = make([]byte, structSize)
		copy(data, rta.Value)
	}
	return LinuxDiagInfoWithRef{(*LinuxDiagInfo)(unsafe.Pointer(&data[0])), data}
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
