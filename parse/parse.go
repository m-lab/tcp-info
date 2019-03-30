package parse

import (
	"errors"
	"log"
	"time"
	"unsafe"

	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/tcp-info/netlink"
	"github.com/m-lab/tcp-info/tcp"
)

var ErrEmptyMessage = errors.New("Message should contain Metadata or RawIDM")

// TODO - better names for ParsedMessage and Wrapper.
func DecodeNetlink(pm *netlink.ParsedMessage) (*Wrapper, error) {
	var err error
	result := Wrapper{}
	result.Timestamp = pm.Timestamp
	if pm.Metadata == nil && pm.RawIDM == nil {
		return nil, ErrEmptyMessage
	}
	result.Metadata = pm.Metadata
	if pm.RawIDM != nil {
		result.InetDiagMsg, err = pm.RawIDM.Parse()
		if err != nil {
			log.Println("Error decoding RawIDM:", err)
			return nil, err
		}
	}
	for i, raw := range pm.Attributes {
		if raw == nil {
			continue
		}
		rta := RouteAttrValue(raw)
		result.FieldMask |= 1 << uint8(i-1)
		switch i {
		case inetdiag.INET_DIAG_MEMINFO:
			result.MemInfo = rta.ToMemInfo()
		case inetdiag.INET_DIAG_INFO:
			result.TcpInfo = rta.ToLinuxTCPInfo()
		case inetdiag.INET_DIAG_VEGASINFO:
			result.VegasInfo = rta.ToVegasInfo()
		case inetdiag.INET_DIAG_CONG:
			result.CongestionAlgorithm = rta.CongestionAlgorithm()
		case inetdiag.INET_DIAG_TOS:
			result.TOS = rta.ToTOS()
		case inetdiag.INET_DIAG_TCLASS:
			result.TClass = rta.ToTCLASS()
		case inetdiag.INET_DIAG_SKMEMINFO:
			result.SocketMem = rta.ToSockMemInfo()
		case inetdiag.INET_DIAG_SHUTDOWN:
			result.Shutdown = rta.ToShutdown()
		case inetdiag.INET_DIAG_DCTCPINFO:
			result.DCTCPInfo = rta.ToDCTCPInfo()
		case inetdiag.INET_DIAG_PROTOCOL:
			result.Protocol = rta.ToProtocol()
		case inetdiag.INET_DIAG_SKV6ONLY:
			log.Println("SKV6ONLY not handled", len(rta))
		case inetdiag.INET_DIAG_LOCALS:
			log.Println("LOCAL not handled", len(rta))
		case inetdiag.INET_DIAG_PEERS:
			log.Println("PEERS not handled", len(rta))
		case inetdiag.INET_DIAG_PAD:
			log.Println("PAD not handled", len(rta))
		case inetdiag.INET_DIAG_MARK:
			result.Mark = rta.ToMark()
		case inetdiag.INET_DIAG_BBRINFO:
			result.BBRInfo = rta.ToBBRInfo()
		case inetdiag.INET_DIAG_CLASS_ID:
			log.Println("CLASS_ID not handled", len(rta))
		case inetdiag.INET_DIAG_MD5SIG:
			log.Println("MD5SIGnot handled", len(rta))
		default:
			// TODO metric so we can alert.
			log.Println("unhandled attribute type:", i)
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
func maybeCopy(src []byte, size int) unsafe.Pointer {
	if len(src) < size {
		data := make([]byte, size)
		copy(data, src)
		return unsafe.Pointer(&data[0])
	}
	// TODO Check for larger than expected, and increment a metric with appropriate label.
	return unsafe.Pointer(&src[0])
}

// ToMemInfo maps the raw RouteAttrValue onto a MemInfo.
func (raw RouteAttrValue) ToMemInfo() *inetdiag.MemInfo {
	structSize := (int)(unsafe.Sizeof(inetdiag.MemInfo{}))
	return (*inetdiag.MemInfo)(maybeCopy(raw, structSize))
}

// ToLinuxTCPInfo maps the raw RouteAttrValue into a LinuxTCPInfo struct.
// For older data, it may have to copy the bytes.
func (raw RouteAttrValue) ToLinuxTCPInfo() *tcp.LinuxTCPInfo {
	structSize := (int)(unsafe.Sizeof(tcp.LinuxTCPInfo{}))
	return (*tcp.LinuxTCPInfo)(maybeCopy(raw, structSize))
}

// ToVegasInfo maps the raw RouteAttrValue onto a VegasInfo.
// For older data, it may have to copy the bytes.
func (raw RouteAttrValue) ToVegasInfo() *inetdiag.VegasInfo {
	structSize := (int)(unsafe.Sizeof(inetdiag.VegasInfo{}))
	return (*inetdiag.VegasInfo)(maybeCopy(raw, structSize))
}

// CongestionAlgorithm returns the congestion algorithm string
// INET_DIAG_CONG
func (raw RouteAttrValue) CongestionAlgorithm() string {
	return string(raw)
}

func (raw RouteAttrValue) toUint8() uint8 {
	if len(raw) < 1 {
		log.Println("Parse error")
		return 0
	}
	return uint8(raw[0])
}

func (raw RouteAttrValue) ToTOS() uint8 {
	return raw.toUint8()
}

func (raw RouteAttrValue) ToTCLASS() uint8 {
	return raw.toUint8()
}

// ToSockMemInfo maps the raw RouteAttrValue onto a SockMemInfo.
// For older data, it may have to copy the bytes.
func (raw RouteAttrValue) ToSockMemInfo() *inetdiag.SocketMemInfo {
	structSize := (int)(unsafe.Sizeof(inetdiag.SocketMemInfo{}))
	return (*inetdiag.SocketMemInfo)(maybeCopy(raw, structSize))
}

func (raw RouteAttrValue) ToShutdown() uint8 {
	return raw.toUint8()
}

// ToVegasInfo maps the raw RouteAttrValue onto a VegasInfo.
// For older data, it may have to copy the bytes.
func (raw RouteAttrValue) ToDCTCPInfo() *inetdiag.DCTCPInfo {
	structSize := (int)(unsafe.Sizeof(inetdiag.DCTCPInfo{}))
	return (*inetdiag.DCTCPInfo)(maybeCopy(raw, structSize))
}

func (raw RouteAttrValue) ToProtocol() inetdiag.Protocol {
	return inetdiag.Protocol(raw.toUint8())
}

func (raw RouteAttrValue) ToMark() uint32 {
	if raw == nil || len(raw) < 4 {
		return 0
	}
	return *(*uint32)(unsafe.Pointer(&raw[0]))
}

// ToBBRInfo maps the raw RouteAttrValue onto a BBRInfo.
// For older data, it may have to copy the bytes.
func (raw RouteAttrValue) ToBBRInfo() *inetdiag.BBRInfo {
	structSize := (int)(unsafe.Sizeof(inetdiag.BBRInfo{}))
	return (*inetdiag.BBRInfo)(maybeCopy(raw, structSize))
}

// Parent containing all info gathered through netlink library.
type Wrapper struct {
	// Timestamp of batch of messages containing this message.
	Timestamp time.Time

	// Metadata for the connection.  Usually empty.
	Metadata *netlink.Metadata

	// Bit field indicating whether each message type was observed.
	FieldMask uint32

	// Info from struct inet_diag_msg, including socket_id;
	InetDiagMsg *inetdiag.InetDiagMsg

	// Data obtained from INET_DIAG_MEMINFO.
	MemInfo *inetdiag.MemInfo

	// Data obtained from struct tcp_info.
	TcpInfo *tcp.LinuxTCPInfo

	VegasInfo *inetdiag.VegasInfo

	// From INET_DIAG_CONG message.
	CongestionAlgorithm string

	TOS    uint8
	TClass uint8

	// Data obtained from INET_DIAG_SKMEMINFO.
	SocketMem *inetdiag.SocketMemInfo

	Shutdown uint8 // TODO do we need an indicator if this is present?

	DCTCPInfo *inetdiag.DCTCPInfo

	// From INET_DIAG_PROTOCOL message.
	Protocol inetdiag.Protocol

	BBRInfo *inetdiag.BBRInfo

	Mark uint32
}
