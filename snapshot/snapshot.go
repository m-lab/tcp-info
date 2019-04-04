// Package snapshot contains code to generate Snapshots from ArchiveRecords, and utilities to
// load them from files.
package snapshot

import (
	"errors"
	"log"
	"time"
	"unsafe"

	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/tcp-info/netlink"
	"github.com/m-lab/tcp-info/tcp"
)

// ErrEmptyRecord is returned if an ArchivalRecord is empty.
var ErrEmptyRecord = errors.New("Message should contain Metadata or RawIDM")

// Decode decodes a netlink.ArchivalRecord into a single Snapshot
func Decode(ar *netlink.ArchivalRecord) (*Snapshot, error) {
	var err error
	result := Snapshot{}
	result.Timestamp = ar.Timestamp
	if ar.Metadata == nil && ar.RawIDM == nil {
		return nil, ErrEmptyRecord
	}
	result.Metadata = ar.Metadata
	if ar.RawIDM != nil {
		result.InetDiagMsg, err = ar.RawIDM.Parse()
		if err != nil {
			log.Println("Error decoding RawIDM:", err)
			return nil, err
		}
	}
	for t, raw := range ar.Attributes {
		if raw == nil {
			continue
		}
		rta := RouteAttrValue(raw)
		ok := false
		switch t {
		case inetdiag.INET_DIAG_MEMINFO:
			result.MemInfo, ok = rta.toMemInfo()
		case inetdiag.INET_DIAG_INFO:
			result.TCPInfo, ok = rta.toLinuxTCPInfo()
		case inetdiag.INET_DIAG_VEGASINFO:
			result.VegasInfo, ok = rta.toVegasInfo()
		case inetdiag.INET_DIAG_CONG:
			result.CongestionAlgorithm, ok = rta.CongestionAlgorithm()
		case inetdiag.INET_DIAG_TOS:
			result.TOS, ok = rta.toTOS()
		case inetdiag.INET_DIAG_TCLASS:
			result.TClass, ok = rta.toTCLASS()
		case inetdiag.INET_DIAG_SKMEMINFO:
			result.SocketMem, ok = rta.toSockMemInfo()
		case inetdiag.INET_DIAG_SHUTDOWN:
			result.Shutdown, ok = rta.toShutdown()
		case inetdiag.INET_DIAG_DCTCPINFO:
			result.DCTCPInfo, ok = rta.toDCTCPInfo()
		case inetdiag.INET_DIAG_PROTOCOL:
			result.Protocol, ok = rta.toProtocol()
		case inetdiag.INET_DIAG_SKV6ONLY:
			log.Println("SKV6ONLY not handled", len(rta))
		case inetdiag.INET_DIAG_LOCALS:
			log.Println("LOCAL not handled", len(rta))
		case inetdiag.INET_DIAG_PEERS:
			log.Println("PEERS not handled", len(rta))
		case inetdiag.INET_DIAG_PAD:
			log.Println("PAD not handled", len(rta))
		case inetdiag.INET_DIAG_MARK:
			result.Mark, ok = rta.toMark()
		case inetdiag.INET_DIAG_BBRINFO:
			result.BBRInfo, ok = rta.toBBRInfo()
		case inetdiag.INET_DIAG_CLASS_ID:
			log.Println("CLASS_ID not handled", len(rta))
		case inetdiag.INET_DIAG_MD5SIG:
			log.Println("MD5SIGnot handled", len(rta))
		default:
			// TODO metric so we can alert.
			log.Println("unhandled attribute type:", t)
		}
		bit := uint32(1) << uint8(t-1)
		result.Observed |= bit
		if !ok {
			result.NotFullyParsed |= bit
		}
	}
	return &result, nil
}

/*********************************************************************************************/
/*          Conversions from RouteAttr.Value to various tcp and inetdiag structs             */
/*********************************************************************************************/

// RouteAttrValue is the type of RouteAttr.Value
type RouteAttrValue []byte

// maybeCopy checks whether the src is the full size of the intended struct size.
// If so, it just returns the pointer, otherwise it copies the content to an
// appropriately sized new byte slice, and returns pointer to that.
func maybeCopy(src []byte, size int) (unsafe.Pointer, bool) {
	if len(src) < size {
		data := make([]byte, size)
		copy(data, src)
		return unsafe.Pointer(&data[0]), true
	}
	// TODO Check for larger than expected, and increment a metric with appropriate label.
	return unsafe.Pointer(&src[0]), len(src) == size
}

// toMemInfo maps the raw RouteAttrValue onto a MemInfo.
func (raw RouteAttrValue) toMemInfo() (*inetdiag.MemInfo, bool) {
	structSize := (int)(unsafe.Sizeof(inetdiag.MemInfo{}))
	data, ok := maybeCopy(raw, structSize)
	if !ok {
		log.Println("not ok")
	}
	return (*inetdiag.MemInfo)(data), ok
}

// toLinuxTCPInfo maps the raw RouteAttrValue into a LinuxTCPInfo struct.
// For older data, it may have to copy the bytes.
func (raw RouteAttrValue) toLinuxTCPInfo() (*tcp.LinuxTCPInfo, bool) {
	structSize := (int)(unsafe.Sizeof(tcp.LinuxTCPInfo{}))
	data, ok := maybeCopy(raw, structSize)
	if !ok {
		log.Println("not ok")
	}
	return (*tcp.LinuxTCPInfo)(data), ok
}

// toVegasInfo maps the raw RouteAttrValue onto a VegasInfo.
// For older data, it may have to copy the bytes.
func (raw RouteAttrValue) toVegasInfo() (*inetdiag.VegasInfo, bool) {
	structSize := (int)(unsafe.Sizeof(inetdiag.VegasInfo{}))
	data, ok := maybeCopy(raw, structSize)
	return (*inetdiag.VegasInfo)(data), ok
}

// CongestionAlgorithm returns the congestion algorithm string
// INET_DIAG_CONG
func (raw RouteAttrValue) CongestionAlgorithm() (string, bool) {
	// This is sometimes empty, but that is valid, so we return true.
	return string(raw[:len(raw)-1]), true
}

func (raw RouteAttrValue) toUint8() (uint8, bool) {
	if len(raw) < 1 {
		return 0, false
	}
	return uint8(raw[0]), true
}

// toTOS marshals the TCP Type Of Service field.  See https://tools.ietf.org/html/rfc3168
func (raw RouteAttrValue) toTOS() (uint8, bool) {
	return raw.toUint8()
}

// toTCLASS marshals the TCP Traffic Class octet.  See https://tools.ietf.org/html/rfc3168
func (raw RouteAttrValue) toTCLASS() (uint8, bool) {
	return raw.toUint8()
}

// toSockMemInfo maps the raw RouteAttrValue onto a SockMemInfo.
// For older data, it may have to copy the bytes.
func (raw RouteAttrValue) toSockMemInfo() (*inetdiag.SocketMemInfo, bool) {
	structSize := (int)(unsafe.Sizeof(inetdiag.SocketMemInfo{}))
	data, ok := maybeCopy(raw, structSize)
	return (*inetdiag.SocketMemInfo)(data), ok
}

func (raw RouteAttrValue) toShutdown() (uint8, bool) {
	return raw.toUint8()
}

// toVegasInfo maps the raw RouteAttrValue onto a VegasInfo.
// For older data, it may have to copy the bytes.
func (raw RouteAttrValue) toDCTCPInfo() (*inetdiag.DCTCPInfo, bool) {
	structSize := (int)(unsafe.Sizeof(inetdiag.DCTCPInfo{}))
	data, ok := maybeCopy(raw, structSize)
	return (*inetdiag.DCTCPInfo)(data), ok
}

func (raw RouteAttrValue) toProtocol() (inetdiag.Protocol, bool) {
	p, ok := raw.toUint8()
	return inetdiag.Protocol(p), ok
}

func (raw RouteAttrValue) toMark() (uint32, bool) {
	if raw == nil || len(raw) != 4 {
		return 0, false
	}
	return *(*uint32)(unsafe.Pointer(&raw[0])), true
}

// toBBRInfo maps the raw RouteAttrValue onto a BBRInfo.
// For older data, it may have to copy the bytes.
func (raw RouteAttrValue) toBBRInfo() (*inetdiag.BBRInfo, bool) {
	structSize := (int)(unsafe.Sizeof(inetdiag.BBRInfo{}))
	data, ok := maybeCopy(raw, structSize)
	return (*inetdiag.BBRInfo)(data), ok
}

// Snapshot contains all info gathered through netlink library.
type Snapshot struct {
	// Timestamp of batch of messages containing this message.
	Timestamp time.Time

	// Metadata for the connection.  Usually empty.
	Metadata *netlink.Metadata

	// Bit field indicating whether each message type was observed.
	Observed uint32

	// Bit field indicating whether any message type was NOT fully parsed.
	// TODO - populate this field if any message is ignored, or not fully parsed.
	NotFullyParsed uint32

	// Info from struct inet_diag_msg, including socket_id;
	InetDiagMsg *inetdiag.InetDiagMsg

	// Data obtained from INET_DIAG_MEMINFO.
	MemInfo *inetdiag.MemInfo

	// TCPInfo contains data from struct tcp_info.
	TCPInfo *tcp.LinuxTCPInfo

	VegasInfo *inetdiag.VegasInfo

	// From INET_DIAG_CONG message.
	CongestionAlgorithm string

	// See https://tools.ietf.org/html/rfc3168
	// TODO Do we need to record whether these are present and zero, vs absent?
	TOS    uint8
	TClass uint8

	// Data obtained from INET_DIAG_SKMEMINFO.
	SocketMem *inetdiag.SocketMemInfo

	// TODO Do we need to record present and zero, vs absent?
	Shutdown uint8

	DCTCPInfo *inetdiag.DCTCPInfo

	// From INET_DIAG_PROTOCOL message.
	// TODO Do we need to record present and zero, vs absent?
	Protocol inetdiag.Protocol

	BBRInfo *inetdiag.BBRInfo

	Mark uint32
}

// ConnectionLog contains a Metadata and slice of Snapshots.
type ConnectionLog struct {
	Metadata  netlink.Metadata
	Snapshots []Snapshot
}

// Reader wraps an ArchiveReader to provide a Snapshot reader.
type Reader struct {
	archiveReader netlink.ArchiveReader
}

// NewReader wraps an ArchiveReader and provides Next()
func NewReader(ar netlink.ArchiveReader) *Reader {
	return &Reader{archiveReader: ar}
}

var zeroTime = time.Time{}

// Next reads, parses and returns the next Snapshot
func (rdr Reader) Next() (*Snapshot, error) {
	ar, err := rdr.archiveReader.Next()
	if err != nil {
		return nil, err
	}

	// HACK
	// Parse doesn't fill the Timestamp, so for now, populate it with something...
	if ar.Timestamp == zeroTime {
		ar.Timestamp = time.Date(2009, time.May, 29, 23, 59, 59, 0, time.UTC)
	}

	return Decode(ar)
}
