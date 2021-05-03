package inetdiag_test

import (
	"log"
	"syscall"
	"testing"
	"unsafe"

	"github.com/m-lab/tcp-info/inetdiag"
)

func init() {
	// Always prepend the filename and line number.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}
func TestSizes(t *testing.T) {
	if unsafe.Offsetof(inetdiag.LinuxSockID{}.IDiagDPort) != 2 {
		t.Error("Incorrect DPort offset")
	}
	if unsafe.Offsetof(inetdiag.LinuxSockID{}.IDiagSrc) != 4 {
		t.Error("Incorrect Src offset")
	}
	if unsafe.Offsetof(inetdiag.LinuxSockID{}.IDiagDst) != 20 {
		t.Error("Incorrect Dest offset")
	}
	if unsafe.Offsetof(inetdiag.LinuxSockID{}.IDiagIf) != 36 {
		t.Error("Incorrect Interface offset")
	}
	if unsafe.Offsetof(inetdiag.LinuxSockID{}.IDiagCookie) != 40 {
		t.Error("Incorrect Cookie offset")
	}
	if unsafe.Sizeof(inetdiag.LinuxSockID{}) != 48 {
		t.Error("LinuxSockID wrong size", unsafe.Sizeof(inetdiag.LinuxSockID{}))
	}

	hdr := inetdiag.InetDiagMsg{}
	if unsafe.Sizeof(hdr) != 4*6+unsafe.Sizeof(inetdiag.LinuxSockID{}) {
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
