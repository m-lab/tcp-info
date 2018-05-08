package inetdiag_test

import (
	"log"
	"syscall"
	"testing"
	"unsafe"

	"github.com/m-lab/tcp-info/inetdiag"
)

// This is not exhaustive, but covers the basics.  Integration tests will expose any more subtle
// problems.

func TestParseInetDiagMsg(t *testing.T) {
	var data [100]byte
	for i := range data {
		data[i] = byte(i + 2)
	}
	hdr, value := inetdiag.ParseInetDiagMsg(data[:])
	if hdr.IDiagFamily != syscall.AF_INET {
		t.Errorf("Failed %+v\n", hdr)
	}
	if hdr.IDiagState != inetdiag.TCP_SYN_RECV {
		t.Errorf("Failed %+v\n", hdr)
	}

	if len(value) != 28 {
		t.Error("Len", len(value))
	}
}

func TestSerialize(t *testing.T) {
	v2 := inetdiag.NewInetDiagReqV2(syscall.AF_INET, 23, 0x0E)
	data := v2.Serialize()
	if v2.Len() != len(data) {
		t.Error("That's odd")
	}
}

func TestID4(t *testing.T) {
	var data [unsafe.Sizeof(inetdiag.InetDiagMsg{})]byte
	srcIPOffset := unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID) + unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID.IDiagSrc)
	data[srcIPOffset] = 127
	data[srcIPOffset+1] = 0
	data[srcIPOffset+2] = 0
	data[srcIPOffset+3] = 1

	srcPortOffset := unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID) + unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID.IDiagSPort)
	// netlink uses host byte ordering, which may or may not be network byte ordering.  So no swapping should be
	// done.
	*(*uint16)(unsafe.Pointer(&data[srcPortOffset])) = 0x1234

	dstIPOffset := unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID) + unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID.IDiagDst)
	data[dstIPOffset] = 1
	data[dstIPOffset+1] = 0
	data[dstIPOffset+2] = 0
	data[dstIPOffset+3] = 127 // Looks like localhost, but its reversed.

	hdr, _ := inetdiag.ParseInetDiagMsg(data[:])
	if !hdr.ID.SrcIP().IsLoopback() {
		log.Println(hdr.ID.SrcIP().IsLoopback())
	}
	if hdr.ID.IDiagSPort != 0x1234 {
		t.Errorf("SPort should be 0x1234 %+v\n", hdr.ID)
	}

	if !hdr.ID.SrcIP().IsLoopback() {
		t.Errorf("Should be identified as loopback")
	}
	if hdr.ID.DstIP().IsLoopback() {
		t.Errorf("Should not be identified as loopback") // Yeah I know this is not self-consistent. :P
	}
}

func TestID6(t *testing.T) {
	var data [unsafe.Sizeof(inetdiag.InetDiagMsg{})]byte
	srcIPOffset := unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID) + unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID.IDiagSrc)
	for i := 0; i < 8; i++ {
		data[srcIPOffset] = byte(0x0A + i)
	}

	dstIPOffset := unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID) + unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID.IDiagDst)
	for i := 0; i < 8; i++ {
		data[dstIPOffset] = byte(i + 1)
	}

	hdr, _ := inetdiag.ParseInetDiagMsg(data[:])

	if hdr.ID.SrcIP().IsLoopback() {
		t.Errorf("Should not be identified as loopback")
	}
	if hdr.ID.DstIP().IsLoopback() {
		t.Errorf("Should not be identified as loopback")
	}
}
