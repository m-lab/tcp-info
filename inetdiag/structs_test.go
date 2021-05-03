package inetdiag

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"testing"
	"unsafe"

	"github.com/gocarina/gocsv"
	"github.com/m-lab/go/anonymize"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/tcp"
)

func init() {
	// Always prepend the filename and line number.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

// This needs to be a whitebox test because it tests unexported types.
func TestStructAndCSVExport(t *testing.T) {
	sid := LinuxSockID{
		IDiagSPort:  Port{2, 1},
		IDiagDPort:  Port{1, 2},
		IDiagSrc:    ipType{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		IDiagDst:    ipType{1, 1, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		IDiagIf:     netIF{0, 0, 2, 1},
		IDiagCookie: cookieType{0xff, 0, 0, 0, 0, 0, 0, 0xff},
	}

	// Verify that each element marshals correctly
	testCases := []struct {
		in  gocsv.TypeMarshaller
		out string
	}{
		{&sid.IDiagSPort, "513"},
		{&sid.IDiagDPort, "258"},
		{&sid.IDiagSrc, "100::2"},
		{&sid.IDiagDst, "1.1.1.2"},
		{&sid.IDiagIf, "513"},
		{&sid.IDiagCookie, "FF000000000000FF"},
	}
	for _, tc := range testCases {
		if s, err := tc.in.MarshalCSV(); err != nil || s != tc.out {
			t.Errorf("%q != %q or error %v != nil", s, tc.out, err)
		}
	}

	// Verify that nothing crashes when the complete struct gets written out.
	buff := bytes.NewBuffer([]byte{})
	rtx.Must(gocsv.Marshal([]LinuxSockID{sid}, buff), "Could not marshal LinuxSockID into a CSV")

	if sid.Interface() != 513 {
		t.Error(sid.Interface(), "!= 513")
	}
	if sid.SrcIP().String() != "100::2" {
		t.Error(sid.SrcIP(), "!= [100::2]")
	}
	if sid.DstIP().String() != "1.1.1.2" {
		t.Error(sid.DstIP(), "!= 1.1.1.2")
	}
	if sid.SPort() != 513 {
		t.Error(sid.SPort(), "!= 513")
	}
	if sid.DPort() != 258 {
		t.Error(sid.DPort(), "!= 258")
	}
	if sid.Cookie() != 0xFF000000000000FF {
		t.Error(sid.Cookie(), " wrong value")
	}

	// This tests that the int64 cast works properly.
	if sid.GetSockID().Cookie != -0xFFFFFFFFFFFF01 {
		t.Error("Bad cookie", sid.GetSockID())
		log.Printf("%X\n", sid.GetSockID().Cookie)
	}
}

func toString(id LinuxSockID) string {
	return fmt.Sprintf("%s:%d -> %s:%d", id.SrcIP().String(), id.SPort(), id.DstIP().String(), id.DPort())
}

func TestParseInetDiagMsg(t *testing.T) {
	var data [100]byte
	for i := range data {
		data[i] = byte(i + 2)
	}
	raw, value := SplitInetDiagMsg(data[:])
	hdr, err := raw.Parse()
	rtx.Must(err, "")

	if hdr.ID.Interface() == 0 || hdr.ID.Cookie() == 0 || hdr.ID.DPort() == 0 || toString(hdr.ID) == "" {
		t.Errorf("None of the accessed values should be zero")
	}
	if hdr.IDiagFamily != AF_INET {
		t.Errorf("Failed %+v\n", hdr)
	}
	if tcp.State(hdr.IDiagState) != tcp.SYN_RECV {
		t.Errorf("Failed %+v\n", hdr)
	}

	if len(value) != 28 {
		t.Error("Len", len(value))
	}

	raw, value = SplitInetDiagMsg(data[:1])
	if raw != nil || value != nil {
		t.Error("This should fail, the data is too small.")
	}
}

func TestID4(t *testing.T) {
	var data [unsafe.Sizeof(InetDiagMsg{})]byte
	srcIPOffset := unsafe.Offsetof(InetDiagMsg{}.ID) + unsafe.Offsetof(InetDiagMsg{}.ID.IDiagSrc)
	data[srcIPOffset] = 127
	data[srcIPOffset+1] = 0
	data[srcIPOffset+2] = 0
	data[srcIPOffset+3] = 1

	srcPortOffset := unsafe.Offsetof(InetDiagMsg{}.ID) + unsafe.Offsetof(InetDiagMsg{}.ID.IDiagSPort)
	// netlink uses host byte ordering, which may or may not be network byte ordering.  So no swapping should be
	// done.
	*(*uint16)(unsafe.Pointer(&data[srcPortOffset])) = 0x1234

	dstIPOffset := unsafe.Offsetof(InetDiagMsg{}.ID) + unsafe.Offsetof(InetDiagMsg{}.ID.IDiagDst)
	data[dstIPOffset] = 1
	data[dstIPOffset+1] = 0
	data[dstIPOffset+2] = 0
	data[dstIPOffset+3] = 127 // Looks like localhost, but its reversed.

	raw, _ := SplitInetDiagMsg(data[:])
	hdr, err := raw.Parse()
	rtx.Must(err, "")
	if !hdr.ID.SrcIP().IsLoopback() {
		t.Errorf("Should be loopback but isn't")
	}
	if hdr.ID.DstIP().IsLoopback() {
		t.Errorf("Shouldn't be loopback but is")
	}
	if hdr.ID.SPort() != 0x3412 {
		t.Errorf("SPort should be 0x3412 %+v\n", hdr.ID)
	}

	if !hdr.ID.SrcIP().IsLoopback() {
		t.Errorf("Should be identified as loopback")
	}
	if hdr.ID.DstIP().IsLoopback() {
		t.Errorf("Should not be identified as loopback") // Yeah I know this is not self-consistent. :P
	}
}

func TestID6(t *testing.T) {
	var data [unsafe.Sizeof(InetDiagMsg{})]byte
	srcIPOffset := unsafe.Offsetof(InetDiagMsg{}.ID) + unsafe.Offsetof(InetDiagMsg{}.ID.IDiagSrc)
	for i := 0; i < 8; i++ {
		data[srcIPOffset] = byte(0x0A + i)
	}

	dstIPOffset := unsafe.Offsetof(InetDiagMsg{}.ID) + unsafe.Offsetof(InetDiagMsg{}.ID.IDiagDst)
	for i := 0; i < 8; i++ {
		data[dstIPOffset] = byte(i + 1)
	}

	raw, _ := SplitInetDiagMsg(data[:])
	hdr, err := raw.Parse()
	rtx.Must(err, "")

	if hdr.ID.SrcIP().IsLoopback() {
		t.Errorf("Should not be identified as loopback")
	}
	if hdr.ID.DstIP().IsLoopback() {
		t.Errorf("Should not be identified as loopback")
	}
}

func TestID4Anonymize(t *testing.T) {
	var data [unsafe.Sizeof(InetDiagMsg{})]byte
	// Setup Src.
	// NOTE: anonymize package identifies 127.0.0.1 as a local IP and declines to anonymize it.
	var srcOrig = [16]byte{10, 4, 3, 2}
	var srcAnon = [16]byte{10, 4, 3, 0}
	srcIPOffset := unsafe.Offsetof(InetDiagMsg{}.ID) + unsafe.Offsetof(InetDiagMsg{}.ID.IDiagSrc)
	data[srcIPOffset] = 10
	data[srcIPOffset+1] = 4
	data[srcIPOffset+2] = 3
	data[srcIPOffset+3] = 2

	// Setup Dst.
	var dstOrig = [16]byte{192, 168, 5, 100}
	var dstAnon = [16]byte{192, 168, 5, 0}
	dstIPOffset := unsafe.Offsetof(InetDiagMsg{}.ID) + unsafe.Offsetof(InetDiagMsg{}.ID.IDiagDst)
	data[dstIPOffset] = 192
	data[dstIPOffset+1] = 168
	data[dstIPOffset+2] = 5
	data[dstIPOffset+3] = 100

	// Setup AF.
	afOffset := unsafe.Offsetof(InetDiagMsg{}.IDiagFamily)
	data[afOffset] = AF_INET

	raw, _ := SplitInetDiagMsg(data[:])
	hdr, err := raw.Parse()
	rtx.Must(err, "Failed to parse InetDiagMsg")

	// Verify anonymize.None does nothing.
	err = raw.Anonymize(anonymize.New(anonymize.None))
	rtx.Must(err, "Failed to anonymize")
	origSrcIP := net.IP(srcOrig[:])
	origDstIP := net.IP(dstOrig[:])
	hdrSrcIP := net.IP(hdr.ID.IDiagSrc[:])
	hdrDstIP := net.IP(hdr.ID.IDiagDst[:])
	if !origSrcIP.Equal(hdrSrcIP) {
		t.Errorf("Anonymize IPs modified using method None! %s != %s", origSrcIP, hdrSrcIP)
	}
	if !origDstIP.Equal(hdrDstIP) {
		t.Errorf("Anonymize IPs modified using method None! %s != %s", origDstIP, hdrDstIP)
	}

	// Verify anonymize.Netblock equals expected anonymized addrs.
	err = raw.Anonymize(anonymize.New(anonymize.Netblock))
	rtx.Must(err, "Failed to anonymize")
	anonSrcIP := net.IP(srcAnon[:])
	anonDstIP := net.IP(dstAnon[:])
	hdrSrcIP = net.IP(hdr.ID.IDiagSrc[:])
	hdrDstIP = net.IP(hdr.ID.IDiagDst[:])
	if !anonSrcIP.Equal(hdrSrcIP) {
		t.Errorf("Anonymize IPs modified using method None! %s != %s", anonSrcIP, hdrSrcIP)
	}
	if !anonDstIP.Equal(hdrDstIP) {
		t.Errorf("Anonymize IPs modified using method None! %s != %s", anonDstIP, hdrDstIP)
	}
}

func TestID6Anonymize(t *testing.T) {
	var data [unsafe.Sizeof(InetDiagMsg{})]byte
	var srcOrig [16]byte
	var dstOrig [16]byte
	var srcAnon [16]byte
	var dstAnon [16]byte
	// Setup src IP.
	srcIPOffset := unsafe.Offsetof(InetDiagMsg{}.ID) + unsafe.Offsetof(InetDiagMsg{}.ID.IDiagSrc)
	for i := 0; i < 16; i++ {
		data[srcIPOffset+uintptr(i)] = byte(0x0A + i)
		srcOrig[i] = byte(0x0A + i)
		if i < 8 {
			srcAnon[i] = srcOrig[i]
		}
	}
	// Setup dst IP.
	dstIPOffset := unsafe.Offsetof(InetDiagMsg{}.ID) + unsafe.Offsetof(InetDiagMsg{}.ID.IDiagDst)
	for i := 0; i < 16; i++ {
		data[dstIPOffset+uintptr(i)] = byte(i + 1)
		dstOrig[i] = byte(i + 1)
		if i < 8 {
			dstAnon[i] = dstOrig[i]
		}
	}
	// Setup AF.
	afOffset := unsafe.Offsetof(InetDiagMsg{}.IDiagFamily)
	data[afOffset] = AF_INET6

	raw, _ := SplitInetDiagMsg(data[:])
	hdr, err := raw.Parse()
	rtx.Must(err, "")

	// Verify anonymize.None does nothing.
	err = raw.Anonymize(anonymize.New(anonymize.None))
	rtx.Must(err, "Failed to anonymize")
	origSrcIP := net.IP(srcOrig[:])
	origDstIP := net.IP(dstOrig[:])
	hdrSrcIP := net.IP(hdr.ID.IDiagSrc[:])
	hdrDstIP := net.IP(hdr.ID.IDiagDst[:])
	if !origSrcIP.Equal(hdrSrcIP) {
		t.Errorf("Anonymize IPs modified using method None! %s != %s", origSrcIP, hdrSrcIP)
	}
	if !origDstIP.Equal(hdrDstIP) {
		t.Errorf("Anonymize IPs modified using method None! %s != %s", origDstIP, hdrDstIP)
	}

	// Verify anonymize.Netblock equals expected anonymized addrs.
	err = raw.Anonymize(anonymize.New(anonymize.Netblock))
	rtx.Must(err, "Failed to anonymize")
	anonSrcIP := net.IP(srcAnon[:])
	anonDstIP := net.IP(dstAnon[:])
	hdrSrcIP = net.IP(hdr.ID.IDiagSrc[:])
	hdrDstIP = net.IP(hdr.ID.IDiagDst[:])
	if !anonSrcIP.Equal(hdrSrcIP) {
		t.Errorf("Anonymize IPs modified using method None! %s != %s", anonSrcIP, hdrSrcIP)
	}
	if !anonDstIP.Equal(hdrDstIP) {
		t.Errorf("Anonymize IPs modified using method None! %s != %s", anonDstIP, hdrDstIP)
	}
}
