package tcpinfo_test

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"syscall"
	"testing"

	"github.com/m-lab/tcp-info/inetdiag"
	tcpinfo "github.com/m-lab/tcp-info/nl-proto"
	"github.com/m-lab/tcp-info/zstd"
	"github.com/vishvananda/netlink/nl"
)

func init() {
	// Always prepend the filename and line number.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

// NextMsg reads the next NetlinkMessage from a source readers.
func nextMsg(rdr io.Reader) (*syscall.NetlinkMessage, error) {
	var header syscall.NlMsghdr
	err := binary.Read(rdr, binary.LittleEndian, &header)
	if err != nil {
		return nil, err
	}
	data := make([]byte, header.Len-uint32(binary.Size(header)))
	err = binary.Read(rdr, binary.LittleEndian, data)
	if err != nil {
		return nil, err
	}

	return &syscall.NetlinkMessage{Header: header, Data: data}, nil
}

// Package error messages
var (
	ErrInetDiagParseFailed = errors.New("Error parsing inetdiag message")
	ErrLocal               = errors.New("Connection is loopback")
	ErrUnknownMessageType  = errors.New("Unknown netlink message type")
)

func convertToProto(msg *syscall.NetlinkMessage, t *testing.T) *tcpinfo.TCPDiagnosticsProto {
	if msg.Header.Type != 20 {
		t.Error("Skipping unknown message type:", msg.Header)
	}
	idm, attrBytes := inetdiag.ParseInetDiagMsg(msg.Data)
	if idm == nil {
		t.Error("Couldn't parse InetDiagMsg")
	}
	srcIP := idm.ID.SrcIP()
	if srcIP.IsLoopback() || srcIP.IsLinkLocalUnicast() || srcIP.IsMulticast() || srcIP.IsUnspecified() {
		return nil
	}
	dstIP := idm.ID.DstIP()
	if dstIP.IsLoopback() || dstIP.IsLinkLocalUnicast() || dstIP.IsMulticast() || dstIP.IsUnspecified() {
		return nil
	}
	type ParsedMessage struct {
		Header      syscall.NlMsghdr
		InetDiagMsg *inetdiag.InetDiagMsg
		Attributes  [inetdiag.INET_DIAG_MAX]*syscall.NetlinkRouteAttr
	}

	parsedMsg := ParsedMessage{Header: msg.Header, InetDiagMsg: idm}
	attrs, err := nl.ParseRouteAttr(attrBytes)
	if err != nil {
		t.Error(err)
	}
	for i := range attrs {
		parsedMsg.Attributes[attrs[i].Attr.Type] = &attrs[i]
	}
	p := tcpinfo.TCPDiagnosticsProto{}
	p.Load(msg.Header, parsedMsg.InetDiagMsg, parsedMsg.Attributes[:])

	return &p
}

func TestReader(t *testing.T) {
	// Cache info new 140  err 0 same 277 local 789 diff 3 total 1209
	// 1209 sockets 143 remotes 403 per iteration
	source := "testdata/testdata.zst"
	log.Println("Reading messages from", source)
	rdr := zstd.NewReader(source)
	parsed := 0
	for {
		msg, err := nextMsg(rdr)
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}

		p := convertToProto(msg, t)
		if p.InetDiagMsg == nil {
			t.Fatal("InetDiagMsg missing")
		}
		if p.CongestionAlgorithm != "cubic" {
			t.Error(p.CongestionAlgorithm, []byte(p.CongestionAlgorithm))
		}
		if p.MemInfo == nil {
			t.Error("MemInfo missing")
		}
		if p.TcpInfo == nil {
			t.Fatal("TcpInfo missing")
		}
		if p.TcpInfo.State != p.InetDiagMsg.State {
			t.Fatal("State mismatch")
		}

		parsed++
	}

	// TODO - do some test on the proto	}
	if parsed != 420 { // 140 new, 277 same, and 3 diff
		t.Error(parsed)
	}
}
