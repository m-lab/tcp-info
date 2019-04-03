package main

import (
	"io"
	"log"
	"os"
	"strings"

	"github.com/gocarina/gocsv"
	"github.com/m-lab/tcp-info/netlink"
	"github.com/m-lab/tcp-info/snapshot"
	"github.com/m-lab/tcp-info/zstd"
)

func init() {
	// Always prepend the filename and line number.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

// TODO handle gs: and local filenames.
// TODO filter a single file from a tar file.
func main() {
	args := os.Args[1:]
	if len(args) != 1 {
		log.Fatal("Must specify filename")
	}

	fn := args[0]

	err := ConvertFileToCSV(fn)
	if err != nil {
		log.Fatal(err)
	}
}

func ConvertFileToCSV(fn string) error {
	var raw io.ReadCloser
	if strings.HasSuffix(fn, ".zst") {
		raw = zstd.NewReader(fn)
		defer raw.Close()
	} else {
		raw, err := os.Open(fn)
		if err != nil {
			return err
		}
		defer raw.Close()
	}

	// Read input from provided filename.
	arReader := netlink.NewArchiveReader(raw)
	snapReader := snapshot.NewReader(arReader)

	// Read all the ParsedMessage and convert to Wrappers.
	snapshots := make([]*snapshot.Snapshot, 0, 3000)
	for {
		snap, err := snapReader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		snapshots = append(snapshots, snap)
	}

	snapshots[0].Metadata = &netlink.Metadata{}

	// Write output to stdout.
	err := gocsv.Marshal(snapshots, os.Stdout)

	if err != nil {
		return err
	}
	return nil
}
