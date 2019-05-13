// Package netlink contains the bare minimum needed to partially parse netlink messages.
package netlink

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"syscall"
	"time"
	"unsafe"

	"github.com/m-lab/tcp-info/tcp"

	"github.com/m-lab/tcp-info/inetdiag"
	"golang.org/x/sys/unix"
)

// Error types.
var (
	ErrNotType20   = errors.New("NetlinkMessage wrong type")
	ErrParseFailed = errors.New("Unable to parse InetDiagMsg")
)

type NetlinkMessage = syscall.NetlinkMessage
type TCPInfo = syscall.TCPInfo

/*********************************************************************************************
*                         Low level netlink message stuff
*********************************************************************************************/

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

// ParseRouteAttr parses a byte array into slice of NetlinkRouteAttr struct.
// Derived from "github.com/vishvananda/netlink/nl/nl_linux.go"
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

/*********************************************************************************************
*          Internal representation of NetlinkJSONL messages
*********************************************************************************************/

// Metadata contains the metadata for a particular TCP stream.
type Metadata struct {
	UUID      string
	Sequence  int
	StartTime time.Time
}

// ArchivalRecord is a container for parsed InetDiag messages and attributes.
type ArchivalRecord struct {
	// Timestamp should be truncated to 1 millisecond for best compression.
	// Using int64 milliseconds instead reduces compressed size by 0.5 bytes/record, or about 1.5%
	Timestamp time.Time `json:",omitempty"`

	// Storing the RawIDM instead of the parsed InetDiagMsg reduces Marshalling by 2.6 usec, and
	// typical compressed size by 3-4 bytes/record
	RawIDM RawInetDiagMsg `json:",omitempty"` // RawInetDiagMsg within NLMsg
	// Saving just the .Value fields reduces Marshalling by 1.9 usec.
	Attributes [][]byte `json:",omitempty"` // byte slices from RouteAttr.Value, backed by NLMsg

	// Metadata contains connection level metadata.  It is typically included in the very first record
	// in a file.
	Metadata *Metadata `json:",omitempty"`
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
	busytimeOffset     = unsafe.Offsetof(tcp.LinuxTCPInfo{}.BusyTime)
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
func (pm *ArchivalRecord) Compare(previous *ArchivalRecord) (ChangeType, error) {
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

	// We now allocate only the size
	if len(previous.Attributes) <= inetdiag.INET_DIAG_INFO || len(pm.Attributes) <= inetdiag.INET_DIAG_INFO {
		return NoTCPInfo, nil
	}
	a := previous.Attributes[inetdiag.INET_DIAG_INFO]
	b := pm.Attributes[inetdiag.INET_DIAG_INFO]
	if a == nil || b == nil {
		return NoTCPInfo, nil
	}

	// If any of the byte/segment/package counters have changed, that is what we are most
	// interested in.
	// NOTE: There are more fields beyond BusyTime, but for now we are ignoring them for diffing purposes.
	if 0 != bytes.Compare(a[pmtuOffset:busytimeOffset], b[pmtuOffset:busytimeOffset]) {
		return StateOrCounterChange, nil
	}

	// Check all the earlier fields, too.  Usually these won't change unless the counters above
	// change, but this way we won't miss something subtle.
	if 0 != bytes.Compare(a[:lastDataSentOffset], b[:lastDataSentOffset]) {
		return StateOrCounterChange, nil
	}

	// If any attributes have been added or removed, that is likely significant.
	if len(previous.Attributes) < len(pm.Attributes) {
		return NewAttribute, nil
	}
	if len(previous.Attributes) > len(pm.Attributes) {
		return LostAttribute, nil
	}
	// Both slices are the same length, check for other differences...
	for tp := range previous.Attributes {
		if tp >= len(pm.Attributes) {
			return LostAttribute, nil
		}
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
/*                            Utilities for loading data                                     */
/*********************************************************************************************/

// LoadRawNetlinkMessage is a simple utility to read the next NetlinkMessage from a source reader,
// e.g. from a file of naked binary netlink messages.
// NOTE: This is a bit fragile if there are any bit errors in the message headers.
func LoadRawNetlinkMessage(rdr io.Reader) (*syscall.NetlinkMessage, error) {
	var header syscall.NlMsghdr
	// TODO - should we pass in LittleEndian as a parameter?
	err := binary.Read(rdr, binary.LittleEndian, &header)
	if err != nil {
		// Note that this may be EOF
		return nil, err
	}
	data := make([]byte, header.Len-uint32(binary.Size(header)))
	err = binary.Read(rdr, binary.LittleEndian, data)
	if err != nil {
		return nil, err
	}

	return &syscall.NetlinkMessage{Header: header, Data: data}, nil
}

// ArchiveReader produces ArchivedRecord structs from some source.
type ArchiveReader interface {
	// Next returns the next ArchivalRecord.  Returns nil, EOF if no more records, or other error if there is a problem.
	Next() (*ArchivalRecord, error)
}

type rawReader struct {
	rdr io.Reader
}

// NewRawReader wraps an io.Reader to create and ArchiveReader
func NewRawReader(rdr io.Reader) ArchiveReader {
	return &rawReader{rdr: rdr}
}

// Next decodes and returns the next ArchivalRecord.
func (raw *rawReader) Next() (*ArchivalRecord, error) {
	msg, err := LoadRawNetlinkMessage(raw.rdr)
	if err != nil {
		return nil, err
	}
	return MakeArchivalRecord(msg, false)
}

type archiveReader struct {
	scanner *bufio.Scanner
}

// NewArchiveReader wraps a source of JSONL ArchiveRecords to create ArchiveReader
func NewArchiveReader(rdr io.Reader) ArchiveReader {
	sc := bufio.NewScanner(rdr)
	return &archiveReader{scanner: sc}
}

// Next decodes and returns the next ArchivalRecord.
func (ar *archiveReader) Next() (*ArchivalRecord, error) {
	if !ar.scanner.Scan() {
		return nil, io.EOF
	}
	buf := ar.scanner.Bytes()

	record := ArchivalRecord{}
	err := json.Unmarshal(buf, &record)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

// LoadAllArchivalRecords reads all PMs from a jsonl stream.
func LoadAllArchivalRecords(rdr io.Reader) ([]*ArchivalRecord, error) {
	msgs := make([]*ArchivalRecord, 0, 2000) // We typically read a large number of records

	pmr := NewArchiveReader(rdr)

	for {
		pm, err := pmr.Next()
		if err != nil {
			if err == io.EOF {
				return msgs, nil
			}
			return msgs, err
		}
		msgs = append(msgs, pm)
	}
}
