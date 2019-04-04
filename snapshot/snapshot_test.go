package snapshot_test

import (
	"io"
	"log"
	"testing"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/tcp-info/netlink"
	"github.com/m-lab/tcp-info/snapshot"
	"github.com/m-lab/tcp-info/zstd"
)

// This is not exhaustive, but covers the basics.  Integration tests will expose any more subtle
// problems.

func init() {
	// Always prepend the filename and line number.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func TestRawReader(t *testing.T) {
	source := "testdata/testdata.zst"
	t.Log("Reading messages from", source)
	rdr := zstd.NewReader(source)
	defer rdr.Close()
	arReader := netlink.NewRawReader(rdr)
	snReader := snapshot.NewReader(arReader)

	defer rdr.Close()

	parsed := int64(0)
	var observed uint32

	for {
		s, err := snReader.Next()
		if err == io.EOF {
			break
		}
		rtx.Must(err, "Could not parse test data")

		observed |= s.Observed
		parsed++
	}

	if observed != (1<<inetdiag.INET_DIAG_MAX)-1 {
		// Uncomment to see which fields are untested.
		// t.Errorf("Fields %0X\n", fields)
	}
	if parsed != 420 {
		t.Error("Wrong count:", parsed)
	}
}

func TestDecodeArchiveRecords(t *testing.T) {
	source := "testdata/archiveRecords.zst"
	t.Log("Reading messages from", source)
	rdr := zstd.NewReader(source)
	defer rdr.Close()
	arReader := netlink.NewArchiveReader(rdr)
	snapReader := snapshot.NewReader(arReader)

	parsed := int64(0)
	var observed uint32

	for {
		snap, err := snapReader.Next()
		if err == io.EOF {
			break
		}
		rtx.Must(err, "Could not parse record")

		observed |= snap.Observed
		parsed++
	}

	if observed != (1<<inetdiag.INET_DIAG_MAX)-1 {
		// Uncomment to see which fields are untested.
		// t.Errorf("Fields %0X\n", fields)
	}
	if parsed != 420 {
		t.Error("Wrong count:", parsed)
	}
}
