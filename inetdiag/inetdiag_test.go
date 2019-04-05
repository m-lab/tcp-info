package inetdiag_test

import (
	"syscall"
	"testing"
	"unsafe"

	"github.com/m-lab/tcp-info/inetdiag"
)

func TestSizes(t *testing.T) {
	if unsafe.Sizeof(inetdiag.SockID{}) != 48 {
		t.Error("SockID wrong size", unsafe.Sizeof(inetdiag.SockID{}))
	}

	hdr := inetdiag.InetDiagMsg{}
	if unsafe.Sizeof(hdr) != 4*6+unsafe.Sizeof(inetdiag.SockID{}) {
		t.Error("Header is wrong size", unsafe.Sizeof(hdr))
	}
}

func TestInetDiagReqV2Serialize(t *testing.T) {
	v2 := inetdiag.NewReqV2(syscall.AF_INET, 23, 0x0E)
	data := v2.Serialize()
	if v2.Len() != len(data) {
		t.Error(data, "should be length", v2.Len())
	}
}
