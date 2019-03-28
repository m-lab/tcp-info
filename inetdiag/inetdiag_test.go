package inetdiag_test

import (
	"testing"
	"unsafe"

	"github.com/m-lab/tcp-info/inetdiag"
)

func TestSizes(t *testing.T) {
	if unsafe.Sizeof(inetdiag.InetDiagSockID{}) != 48 {
		t.Error("SockID wrong size", unsafe.Sizeof(inetdiag.InetDiagSockID{}))
	}

	hdr := inetdiag.InetDiagMsg{}
	if unsafe.Sizeof(hdr) != 4*6+unsafe.Sizeof(inetdiag.InetDiagSockID{}) {
		t.Error("Header is wrong size", unsafe.Sizeof(hdr))
	}
}
