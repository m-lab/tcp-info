// Main package in csvtool implements a command line tool for converting ArchiveRecord files to CSV files.
// See cmd/csvtool/README.md for more information.
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

// TODO handle gs: filenames.
// TODO filter a single file from a tar file.
func main() {
	args := os.Args[1:]
	if len(args) != 1 {
		log.Fatal("Must specify filename")
	}

	fn := args[0]

	err := fileToCSV(fn, os.Stdout)
	if err != nil {
		log.Fatal(err)
	}
}

func toCSV(rdr io.Reader, wtr io.Writer) error {
	// Read input from provided filename.
	arReader := netlink.NewArchiveReader(rdr)
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

	if len(snapshots) > 0 && snapshots[0].Metadata == nil {
		// Add empty Metadata.
		snapshots[0].Metadata = &netlink.Metadata{}
	}

	err := gocsv.Marshal(snapshots, wtr)
	return err
}

// fileToCSV parses ArchiveRecords from file (or "-" for stdin), and write CSV to stdout
func fileToCSV(fn string, wtr io.Writer) error {
	var raw io.ReadCloser
	if strings.HasSuffix(fn, ".zst") {
		raw = zstd.NewReader(fn)
		defer raw.Close()
	} else if fn == "-" {
		raw = os.Stdin
	} else {
		raw, err := os.Open(fn)
		if err != nil {
			return err
		}
		defer raw.Close()
	}

	return toCSV(raw, wtr)
}
