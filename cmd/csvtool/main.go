// Main package in csvtool implements a command line tool for converting ArchiveRecord files to CSV files.
// See cmd/csvtool/README.md for more information.
package main

import (
	"io"
	"log"
	"os"
	"strings"

	"github.com/gocarina/gocsv"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/netlink"
	"github.com/m-lab/tcp-info/snapshot"
	"github.com/m-lab/tcp-info/zstd"
)

func init() {
	// Always prepend the filename and line number.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

var (
	// A variable to enable mocking for testing.
	logFatal = log.Fatal
)

func toCSV(snapshots []*snapshot.Snapshot, wtr io.Writer) error {
	return gocsv.Marshal(snapshots, wtr)
}

// openFile either opens a file, or opens and unzips a file that ends with .zst
func openFile(fn string) (io.ReadCloser, error) {
	if strings.HasSuffix(fn, ".zst") {
		return zstd.NewReader(fn), nil
	}
	return os.Open(fn)
}

// TODO handle gs: filenames.
// TODO filter a single file from a tar file.
func main() {
	args := os.Args[1:]

	var source io.ReadCloser
	var err error
	source = os.Stdin
	if len(args) == 1 {
		source, err = openFile(args[0])
		rtx.Must(err, "Could not open file %q", args[0])
	} else if len(args) > 1 {
		logFatal("Too many command-line arguments.")
	}
	defer source.Close()

	arReader := netlink.NewArchiveReader(source)
	// Ignore the metadata for now.
	_, snaps, err := snapshot.LoadAll(arReader)
	rtx.Must(err, "Could not read snapshots")
	rtx.Must(toCSV(snaps, os.Stdout), "Could not convert input to CSV")
}
