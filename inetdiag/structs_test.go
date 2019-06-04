package inetdiag

import (
	"bytes"
	"fmt"
	"syscall"
	"testing"
	"unsafe"

	"github.com/gocarina/gocsv"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/tcp"
)

// This needs to be a whitebox test because it tests unexported types.
func TestStructAndCSVExport(t *testing.T) {
	sid := LinuxSockID{
		IDiagSPort:  Port{2, 1},
		IDiagDPort:  Port{1, 2},
		IDiagSrc:    ipType{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		IDiagDst:    ipType{1, 1, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		IDiagIf:     netIF{0, 0, 2, 1},
		IDiagCookie: cookieType{0xff, 0, 0, 0, 0, 0, 0, 0},
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
		{&sid.IDiagCookie, "FF"},
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
	if sid.Cookie() != 255 {
		t.Error(sid.Cookie(), "!= 255")
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
	if hdr.IDiagFamily != syscall.AF_INET {
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
