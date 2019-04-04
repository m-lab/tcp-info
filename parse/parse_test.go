package parse_test

import (
	"io"
	"log"
	"testing"
	"time"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/tcp-info/netlink"
	"github.com/m-lab/tcp-info/parse"
	"github.com/m-lab/tcp-info/zstd"
)

// This is not exhaustive, but covers the basics.  Integration tests will expose any more subtle
// problems.

func init() {
	// Always prepend the filename and line number.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

// TODO - should produce and use intermediate message file.
func TestDecoding(t *testing.T) {
	source := "testdata/testdata.zst"
	log.Println("Reading messages from", source)
	rdr := zstd.NewReader(source)
	parsed := int64(0)
	var observed uint32
	for {
		raw, err := netlink.LoadNext(rdr)
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}

		pm, err := netlink.ParseRecord(raw, false)
		rtx.Must(err, "Could not parse test data")
		// Parse doesn't fill the Timestamp, so for now, populate it with something...
		pm.Timestamp = time.Date(2009, time.May, 29, 23, 59, 59, 0, time.UTC)

		snapshot, err := parse.DecodeNetlink(pm)
		if err != nil {
			t.Error(err)
		}
		observed |= snapshot.Observed
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
