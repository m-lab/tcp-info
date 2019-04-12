package inetdiag

import (
	"bytes"
	"testing"

	"github.com/gocarina/gocsv"
	"github.com/m-lab/go/rtx"
)

// This needs to be a whitebox test because it tests unexported types.
func TestStructAndCSVExport(t *testing.T) {
	sid := SockID{
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
	rtx.Must(gocsv.Marshal([]SockID{sid}, buff), "Could not marshal SockID into a CSV")

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
