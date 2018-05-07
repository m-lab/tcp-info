package inetdiag_test

import (
	"syscall"
	"testing"

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
