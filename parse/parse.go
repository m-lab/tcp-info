package parse

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"syscall"
	"time"
	"unsafe"

	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/tcp-info/tcp"
	"golang.org/x/sys/unix"
)

// Error types.
var (
	ErrNotType20   = errors.New("NetlinkMessage wrong type")
	ErrParseFailed = errors.New("Unable to parse InetDiagMsg")
)

// RawInetDiagMsg holds the []byte representation of an InetDiagMsg
type RawInetDiagMsg []byte

// Parse returns the InetDiagMsg itself
// Modified from original to also return attribute data array.
func (raw RawInetDiagMsg) Parse() (*inetdiag.InetDiagMsg, error) {
	align := rtaAlignOf(int(unsafe.Sizeof(inetdiag.InetDiagMsg{})))
	if len(raw) < align {
		return nil, ErrParseFailed
	}
	return (*inetdiag.InetDiagMsg)(unsafe.Pointer(&raw[0])), nil
}

func splitInetDiagMsg(data []byte) (RawInetDiagMsg, []byte) {
	align := rtaAlignOf(int(unsafe.Sizeof(inetdiag.InetDiagMsg{})))
	if len(data) < align {
		log.Println("Wrong length", len(data), "<", align)
		log.Println(data)
		return nil, nil
	}
	return RawInetDiagMsg(data[:align]), data[align:]
}

// RawNlMsgHdr contains a byte slice version of a syscall.NlMsgHdr
type RawNlMsgHdr []byte

// Parse returns the syscall.NlMsghdr
func (raw RawNlMsgHdr) Parse() (*syscall.NlMsghdr, error) {
	size := int(unsafe.Sizeof(syscall.NlMsghdr{}))
	if len(raw) != size {
		return nil, ErrParseFailed
	}
	return (*syscall.NlMsghdr)(unsafe.Pointer(&raw[0])), nil
}

// Metadata contains the metadata for a particular TCP stream.
type Metadata struct {
	UUID      string
	Sequence  int
	StartTime time.Time
}

// ParsedMessage is a container for parsed InetDiag messages and attributes.
type ParsedMessage struct {
	// Timestamp should be truncated to 1 millisecond for best compression.
	// Using int64 milliseconds instead reduces compressed size by 0.5 bytes/record, or about 1.5%
	Timestamp time.Time `json:",omitempty"`

	// Storing the RawIDM instead of the parsed InetDiagMsg reduces Marshalling by 2.6 usec, and
	// typical compressed size by 3-4 bytes/record
	RawIDM RawInetDiagMsg `json:",omitempty"` // RawInetDiagMsg within NLMsg
	// Saving just the .Value fields reduces Marshalling by 1.9 usec.
	Attributes []RouteAttrValue `json:",omitempty"` // RouteAttr.Value, backed by NLMsg
	Metadata   *Metadata        `json:",omitempty"`
}

// ParseNetlinkMessage parses the NetlinkMessage into a ParsedMessage.  If skipLocal is true, it will return nil for
// loopback, local unicast, multicast, and unspecified connections.
// Note that Parse does not populate the Timestamp field, so caller should do so.
func ParseNetlinkMessage(msg *syscall.NetlinkMessage, skipLocal bool) (*ParsedMessage, error) {
	if msg.Header.Type != 20 {
		return nil, ErrNotType20
	}
	raw, attrBytes := splitInetDiagMsg(msg.Data)
	if raw == nil {
		return nil, ErrParseFailed
	}
	if skipLocal {
		idm, err := raw.Parse()
		if err != nil {
			return nil, err
		}

		if isLocal(idm.ID.SrcIP()) || isLocal(idm.ID.DstIP()) {
			return nil, nil
		}
	}

	parsedMsg := ParsedMessage{RawIDM: raw}
	// parsedMsg.NLMsgHdr = &msg.Header

	attrs, err := ParseRouteAttr(attrBytes)
	if err != nil {
		return nil, err
	}
	maxAttrType := uint16(0)
	for _, a := range attrs {
		t := a.Attr.Type
		if t > maxAttrType {
			maxAttrType = t
		}
	}
	if maxAttrType > 2*inetdiag.INET_DIAG_MAX {
		maxAttrType = 2 * inetdiag.INET_DIAG_MAX
	}
	parsedMsg.Attributes = make([]RouteAttrValue, maxAttrType+1, maxAttrType+1)
	for _, a := range attrs {
		t := a.Attr.Type
		if t > maxAttrType {
			log.Println("Error!! Received RouteAttr with very large Type:", t)
			continue
		}
		parsedMsg.Attributes[t] = a.Value
	}
	return &parsedMsg, nil
}

// ChangeType indicates why a new record is worthwhile saving.
type ChangeType int

// Constants to describe the degree of change between two different ParsedMessages.
const (
	NoMajorChange        ChangeType = iota
	IDiagStateChange                // The IDiagState changed
	NoTCPInfo                       // There is no TCPInfo attribute
	NewAttribute                    // There is a new attribute
	LostAttribute                   // There is a dropped attribute
	AttributeLength                 // The length of an attribute changed
	StateOrCounterChange            // One of the early fields in DIAG_INFO changed.
	PacketCountChange               // One of the packet/byte/segment counts (or other late field) changed
	PreviousWasNil                  // The previous message was nil
	Other                           // Some other attribute changed
)

// Useful offsets for Compare
const (
	lastDataSentOffset = unsafe.Offsetof(syscall.TCPInfo{}.Last_data_sent)
	pmtuOffset         = unsafe.Offsetof(syscall.TCPInfo{}.Pmtu)
)

func isLocal(addr net.IP) bool {
	return addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified()
}

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
func (pm *ParsedMessage) Compare(previous *ParsedMessage) (ChangeType, error) {
	if previous == nil {
		return PreviousWasNil, nil
	}
	// If the TCP state has changed, that is important!
	prevIDM, err := previous.RawIDM.Parse()
	if err != nil {
		return NoMajorChange, ErrParseFailed
	}
	pmIDM, err := pm.RawIDM.Parse()
	if err != nil {
		return NoMajorChange, ErrParseFailed
	}
	if prevIDM.IDiagState != pmIDM.IDiagState {
		return IDiagStateChange, nil
	}

	// TODO - should we validate that ID matches?  Otherwise, we shouldn't even be comparing the rest.

	a := previous.Attributes[inetdiag.INET_DIAG_INFO]
	b := pm.Attributes[inetdiag.INET_DIAG_INFO]
	if a == nil || b == nil {
		return NoTCPInfo, nil
	}

	// If any of the byte/segment/package counters have changed, that is what we are most
	// interested in.
	if 0 != bytes.Compare(a[pmtuOffset:], b[pmtuOffset:]) {
		return StateOrCounterChange, nil
	}

	// Check all the earlier fields, too.  Usually these won't change unless the counters above
	// change, but this way we won't miss something subtle.
	if 0 != bytes.Compare(a[:lastDataSentOffset], b[:lastDataSentOffset]) {
		return StateOrCounterChange, nil
	}

	// If any attributes have been added or removed, that is likely significant.
	for tp := range previous.Attributes {
		switch tp {
		case inetdiag.INET_DIAG_INFO:
			// Handled explicitly above.
		default:
			// Detect any change in anything other than INET_DIAG_INFO
			a := previous.Attributes[tp]
			b := pm.Attributes[tp]
			if a == nil && b != nil {
				return NewAttribute, nil
			}
			if a != nil && b == nil {
				return LostAttribute, nil
			}
			if a == nil && b == nil {
				continue
			}
			if len(a) != len(b) {
				return AttributeLength, nil
			}
			// All others we want to be identical
			if 0 != bytes.Compare(a, b) {
				return Other, nil
			}
		}
	}

	return NoMajorChange, nil
}

/*********************************************************************************************/
/*             Utility function to load test data
/*********************************************************************************************/

// LoadNext is a simple utility to read the next NetlinkMessage from a source reader,
// e.g. from a file of saved netlink messages.
func LoadNext(rdr io.Reader) (*syscall.NetlinkMessage, error) {
	var header syscall.NlMsghdr
	// TODO - should we pass in LittleEndian as a parameter?
	err := binary.Read(rdr, binary.LittleEndian, &header)
	if err != nil {
		// Note that this may be EOF
		return nil, err
	}
	//log.Printf("%+v\n", header)
	data := make([]byte, header.Len-uint32(binary.Size(header)))
	err = binary.Read(rdr, binary.LittleEndian, data)
	if err != nil {
		return nil, err
	}

	return &syscall.NetlinkMessage{Header: header, Data: data}, nil
}

/*********************************************************************************************/
/*             Copied from "github.com/vishvananda/netlink/nl/nl_linux.go"                   */
/*********************************************************************************************/

// ParseRouteAttr parses a byte array into a NetlinkRouteAttr struct.
func ParseRouteAttr(b []byte) ([]syscall.NetlinkRouteAttr, error) {
	var attrs []syscall.NetlinkRouteAttr
	for len(b) >= unix.SizeofRtAttr {
		a, vbuf, alen, err := netlinkRouteAttrAndValue(b)
		if err != nil {
			return nil, err
		}
		ra := syscall.NetlinkRouteAttr{Attr: syscall.RtAttr(*a), Value: vbuf[:int(a.Len)-unix.SizeofRtAttr]}
		attrs = append(attrs, ra)
		b = b[alen:]
	}
	return attrs, nil
}

// rtaAlignOf rounds the length of a netlink route attribute up to align it properly.
func rtaAlignOf(attrlen int) int {
	return (attrlen + unix.RTA_ALIGNTO - 1) & ^(unix.RTA_ALIGNTO - 1)
}

func netlinkRouteAttrAndValue(b []byte) (*unix.RtAttr, []byte, int, error) {
	a := (*unix.RtAttr)(unsafe.Pointer(&b[0]))
	if int(a.Len) < unix.SizeofRtAttr || int(a.Len) > len(b) {
		return nil, nil, 0, unix.EINVAL
	}
	return a, b[unix.SizeofRtAttr:], rtaAlignOf(int(a.Len)), nil
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

// ToLinuxTCPInfo maps the raw RouteAttrValue into a LinuxTCPInfo struct.
// For older data, it may have to copy the bytes.
func (raw RouteAttrValue) ToLinuxTCPInfo() *tcp.LinuxTCPInfo {
	structSize := (int)(unsafe.Sizeof(tcp.LinuxTCPInfo{}))
	return (*tcp.LinuxTCPInfo)(maybeCopy(raw, structSize))
}

// ToSockMemInfo maps the raw RouteAttrValue onto a SockMemInfo.
// For older data, it may have to copy the bytes.
func (raw RouteAttrValue) ToSockMemInfo() *inetdiag.SocketMemInfo {
	structSize := (int)(unsafe.Sizeof(inetdiag.SocketMemInfo{}))
	return (*inetdiag.SocketMemInfo)(maybeCopy(raw, structSize))
}

// ToMemInfo maps the raw RouteAttrValue onto a MemInfo.
func (raw RouteAttrValue) ToMemInfo() *inetdiag.MemInfo {
	structSize := (int)(unsafe.Sizeof(inetdiag.MemInfo{}))
	return (*inetdiag.MemInfo)(maybeCopy(raw, structSize))
}

// ToBBRInfo maps the raw RouteAttrValue onto a BBRInfo.
// For older data, it may have to copy the bytes.
func (raw RouteAttrValue) ToBBRInfo() *inetdiag.BBRInfo {
	structSize := (int)(unsafe.Sizeof(inetdiag.BBRInfo{}))
	return (*inetdiag.BBRInfo)(maybeCopy(raw, structSize))
}

// ParseCong returns the congestion algorithm string
func (raw *RouteAttrValue) Cong(rta *syscall.NetlinkRouteAttr) string {
	return string(rta.Value[:len(rta.Value)-1])
}

// Parent containing all info gathered through netlink library.
type Wrapper struct {
	// Info from struct inet_diag_msg, including socket_id;
	InetDiagMsg *inetdiag.InetDiagMsg

	// From INET_DIAG_PROTOCOL message.
	DiagProtocol inetdiag.Protocol

	// From INET_DIAG_CONG message.
	CongestionAlgorithm string

	// The following three are mutually exclusive, as they provide
	// data from different congestion control strategies.
	//Vegas *VegasInfo
	BBR *inetdiag.BBRInfo
	//DCTCP *DCTCPInfo

	// Data obtained from INET_DIAG_SKMEMINFO.
	SocketMem *inetdiag.SocketMemInfo

	// Data obtained from INET_DIAG_MEMINFO.
	MemInfo *inetdiag.MemInfo

	// Data obtained from struct tcp_info.
	TcpInfo *tcp.LinuxTCPInfo

	// TODO
	// If there is shutdown info, this is the mask value.
	// Check has_shutdown_mask to determine whether present.
	//
	// Types that are valid to be assigned to Shutdown:
	//	*TCPDiagnosticsProto_ShutdownMask
	// Shutdown isTCPDiagnosticsProto_Shutdown

	// Timestamp of batch of messages containing this message.
	Timestamp int64
}
