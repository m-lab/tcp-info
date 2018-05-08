package inetdiag_test

import (
	"log"
	"syscall"
	"testing"
	"unsafe"

	"github.com/m-lab/tcp-info/inetdiag"
)

// TODO This will have modest test coverage indirectly through tests that parse syscall.NetlinkMessage
// containing InetDiag messages.  However, probably should have some basic tests here.

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
	for i := 0; i < 8; i++ {
		data[i] = byte(i + 2)
	}
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
	data[dstIPOffset] = 0
	data[dstIPOffset+1] = 0
	data[dstIPOffset+2] = 0
	data[dstIPOffset+3] = 0
	data[dstIPOffset+7] = 0xAA

	dstPortOffset := unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID) + unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID.IDiagDPort)
	// netlink uses host byte ordering, which may or may not be network byte ordering.  So no swapping should be
	// done.
	*(*uint16)(unsafe.Pointer(&data[dstPortOffset])) = 0x4321

	hdr, _ := inetdiag.ParseInetDiagMsg(data[:])
	if !hdr.ID.SrcIP().IsLoopback() {
		log.Println(hdr.ID.SrcIP().IsLoopback())
	}
	if hdr.ID.IDiagSPort != 0x1234 {
		t.Errorf("SPort should be 0x1234 %+v\n", hdr.ID)
	}

	if !hdr.ID.SrcIP().IsLoopback() {
		t.Errorf("Should be identified as local")
	}
	if hdr.ID.DstIP().IsLoopback() {
		t.Errorf("Should not be identified as local")
	}
}

func TestID6(t *testing.T) {
	var data [unsafe.Sizeof(inetdiag.InetDiagMsg{})]byte
	for i := 0; i < 8; i++ {
		data[i] = byte(i + 2)
	}
	srcIPOffset := unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID) + unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID.IDiagSrc)
	data[srcIPOffset] = 0x0A
	data[srcIPOffset+1] = 0x0B
	data[srcIPOffset+2] = 0x0C
	data[srcIPOffset+3] = 0x0D
	data[srcIPOffset+4] = 0x0E
	data[srcIPOffset+5] = 0x0F
	data[srcIPOffset+6] = 0x00
	data[srcIPOffset+7] = 0x01

	srcPortOffset := unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID) + unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID.IDiagSPort)
	// netlink uses host byte ordering, which may or may not be network byte ordering.  So no swapping should be
	// done.
	*(*uint16)(unsafe.Pointer(&data[srcPortOffset])) = 0x1234

	dstIPOffset := unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID) + unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID.IDiagDst)
	data[dstIPOffset] = 0x01
	data[dstIPOffset+1] = 0x02
	data[dstIPOffset+2] = 0x03
	data[dstIPOffset+3] = 0x04
	data[dstIPOffset+4] = 0x05
	data[dstIPOffset+5] = 0x06
	data[dstIPOffset+6] = 0x07
	data[dstIPOffset+7] = 0x0f

	dstPortOffset := unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID) + unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID.IDiagDPort)
	// netlink uses host byte ordering, which may or may not be network byte ordering.  So no swapping should be
	// done.
	*(*uint16)(unsafe.Pointer(&data[dstPortOffset])) = 0x4321

	hdr, _ := inetdiag.ParseInetDiagMsg(data[:])

	if hdr.ID.SrcIP().IsLoopback() {
		t.Errorf("Should not be identified as loopback")
	}
	if hdr.ID.DstIP().IsLoopback() {
		t.Errorf("Should not be identified as loopback")
	}
}
