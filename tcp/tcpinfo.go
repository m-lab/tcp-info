// Package tcp provides TCP state constants and string coversions for those
// constants.
package tcp

import "fmt"

// State is the enumeration of TCP states.
// https://datatracker.ietf.org/doc/draft-ietf-tcpm-rfc793bis/
// and uapi/linux/tcp.h
type State int32

// All of these constants' names make the linter complain, but we inherited
// these names from external C code, so we will keep them.
const (
	INVALID     State = 0
	ESTABLISHED State = 1
	SYN_SENT    State = 2
	SYN_RECV    State = 3
	FIN_WAIT1   State = 4
	FIN_WAIT2   State = 5
	TIME_WAIT   State = 6
	CLOSE       State = 7
	CLOSE_WAIT  State = 8
	LAST_ACK    State = 9
	LISTEN      State = 10
	CLOSING     State = 11
)

// AllFlags includes flag bits for all TCP connection states. It corresponds to TCPF_ALL in some linux code.
const AllFlags = 0xFFF

var stateName = map[State]string{
	0:  "INVALID",
	1:  "ESTABLISHED",
	2:  "SYN_SENT",
	3:  "SYN_RECV",
	4:  "FIN_WAIT1",
	5:  "FIN_WAIT2",
	6:  "TIME_WAIT",
	7:  "CLOSE",
	8:  "CLOSE_WAIT",
	9:  "LAST_ACK",
	10: "LISTEN",
	11: "CLOSING",
}

func (x State) String() string {
	s, ok := stateName[x]
	if !ok {
		return fmt.Sprintf("UNKNOWN_STATE_%d", x)
	}
	return s
}

// LinuxTCPInfo is the linux defined structure returned in RouteAttr DIAG_INFO messages.
// It corresponds to the struct tcp_info in
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/tcp.h
type LinuxTCPInfo struct {
	State       uint8 `csv:"TCP.State"`
	CAState     uint8 `csv:"TCP.CAState"`
	Retransmits uint8 `csv:"TCP.Retransmits"`
	Probes      uint8 `csv:"TCP.Probes"`
	Backoff     uint8 `csv:"TCP.Backoff"`
	Options     uint8 `csv:"TCP.Options"`
	WScale      uint8 `csv:"TCP.WScale"`     //snd_wscale : 4, tcpi_rcv_wscale : 4;
	AppLimited  uint8 `csv:"TCP.AppLimited"` //delivery_rate_app_limited:1;

	RTO    uint32 `csv:"TCP.RTO"` // offset 8
	ATO    uint32 `csv:"TCP.ATO"`
	SndMSS uint32 `csv:"TCP.SndMSS"`
	RcvMSS uint32 `csv:"TCP.RcvMSS"`

	Unacked uint32 `csv:"TCP.Unacked"` // offset 24
	Sacked  uint32 `csv:"TCP.Sacked"`
	Lost    uint32 `csv:"TCP.Lost"`
	Retrans uint32 `csv:"TCP.Retrans"`
	Fackets uint32 `csv:"TCP.Fackets"`

	/* Times. */
	// These seem to be elapsed time, so they increase on almost every sample.
	// We can probably use them to get more info about intervals between samples.
	LastDataSent uint32 `csv:"TCP.LastDataSent"` // offset 44
	LastAckSent  uint32 `csv:"TCP.LastAckSent"`  /* Not remembered, sorry. */ // offset 48
	LastDataRecv uint32 `csv:"TCP.LastDataRecv"` // offset 52
	LastAckRecv  uint32 `csv:"TCP.LastDataRecv"` // offset 56

	/* Metrics. */
	PMTU        uint32 `csv:"TCP.PMTU"`
	RcvSsThresh uint32 `csv:"TCP.RcvSsThresh"`
	RTT         uint32 `csv:"TCP.RTT"`
	RTTVar      uint32 `csv:"TCP.RTTVar"`
	SndSsThresh uint32 `csv:"TCP.SndSsThresh"`
	SndCwnd     uint32 `csv:"TCP.SndCwnd"`
	AdvMSS      uint32 `csv:"TCP.AdvMSS"`
	Reordering  uint32 `csv:"TCP.Reordering"`

	RcvRTT   uint32 `csv:"TCP.RcvRTT"`
	RcvSpace uint32 `csv:"TCP.RcvSpace"`

	TotalRetrans uint32 `csv:"TCP.TotalRetrans"`

	PacingRate    int64 `csv:"TCP.PacingRate"`    // This is often -1, so better for it to be signed
	MaxPacingRate int64 `csv:"TCP.MaxPacingRate"` // This is often -1, so better to be signed.

	// NOTE: In linux, these are uint64, but we make them int64 here for compatibility with BigQuery
	BytesAcked    int64 `csv:"TCP.BytesAcked"`    /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
	BytesReceived int64 `csv:"TCP.BytesReceived"` /* RFC4898 tcpEStatsAppHCThruOctetsReceived */
	SegsOut       int32 `csv:"TCP.SegsOut"`       /* RFC4898 tcpEStatsPerfSegsOut */
	SegsIn        int32 `csv:"TCP.SegsIn"`        /* RFC4898 tcpEStatsPerfSegsIn */

	NotsentBytes uint32 `csv:"TCP.NotsentBytes"`
	MinRTT       uint32 `csv:"TCP.MinRTT"`
	DataSegsIn   uint32 `csv:"TCP.DataSegsIn"`  /* RFC4898 tcpEStatsDataSegsIn */
	DataSegsOut  uint32 `csv:"TCP.DataSegsOut"` /* RFC4898 tcpEStatsDataSegsOut */

	// NOTE: In linux, this is uint64, but we make it int64 here for compatibility with BigQuery
	DeliveryRate int64 `csv:"TCP.DeliveryRate"`

	BusyTime      int64 `csv:"TCP.BusyTime"`      /* Time (usec) busy sending data */
	RWndLimited   int64 `csv:"TCP.RWndLimited"`   /* Time (usec) limited by receive window */
	SndBufLimited int64 `csv:"TCP.SndBufLimited"` /* Time (usec) limited by send buffer */

	Delivered   uint32 `csv:"TCP.Delivered"`
	DeliveredCE uint32 `csv:"TCP.DeliveredCE"`

	// NOTE: In linux, these are uint64, but we make them int64 here for compatibility with BigQuery
	BytesSent    int64 `csv:"TCP.BytesSent"`    /* RFC4898 tcpEStatsPerfHCDataOctetsOut */
	BytesRetrans int64 `csv:"TCP.BytesRetrans"` /* RFC4898 tcpEStatsPerfOctetsRetrans */

	DSackDups uint32 `csv:"TCP.DSackDups"` /* RFC4898 tcpEStatsStackDSACKDups */
	ReordSeen uint32 `csv:"TCP.ReordSeen"` /* reordering events seen */

	RcvOooPack uint32 `csv:"TCP.RcvOooPack"` /* Out-of-order packets received */

	SndWnd uint32 `csv:"TCP.SndWnd"` /* peer's advertised receive window after scaling (bytes) */
}
