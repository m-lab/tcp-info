package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/snapshot"
)

func TestMainTooManyArgs(t *testing.T) {
	defer func(args []string) {
		os.Args = args
		logFatal = log.Fatal
	}(os.Args)

	os.Args = []string{"test_csvtool", "file1", "file2"}
	logFatal = func(...interface{}) {
		panic("panic instead of log.Fatal")
	}

	defer func() {
		e := recover()
		if e == nil {
			t.Error("Should have panicked")
		}
	}()

	main()
}

func TestMain(t *testing.T) {
	defer func(args []string) {
		os.Args = args
	}(os.Args)

	// Nothing crashes when we pass in a valid file.
	os.Args = []string{"test_csvtool", "testdata/ndt-jdczh_1553815964_00000000000003E8.00183.jsonl.zst"}
	main()
}

func TestOpenFile(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestOpenFile")
	rtx.Must(err, "Could not make tempdir")
	defer os.RemoveAll(dir)
	rtx.Must(ioutil.WriteFile(dir+"/test.txt", []byte("abcd"), 0666), "Could not write test.txt")
	r, err := openFile(dir + "/test.txt")
	rtx.Must(err, "Could not open file")
	b, err := ioutil.ReadAll(r)
	rtx.Must(err, "Could not read file")
	if string(b) != "abcd" {
		t.Errorf("%q != \"abcd\"", string(b))
	}
}

func TestFileToCSV(t *testing.T) {
	src, err := openFile("testdata/ndt-jdczh_1553815964_00000000000003E8.00183.jsonl.zst")
	rtx.Must(err, "Could not open file")
	buf := bytes.NewBuffer(nil)
	snaps, err := readSnapshots(src)
	rtx.Must(err, "Could not read test data")

	err = toCSV(snaps, buf)

	if err != nil {
		t.Fatal("Conversion problem", err)
	}

	out := string(buf.Bytes())
	lines := strings.Split(out, "\n")
	// Split introduces one final empty string, so with the header, the total is 153.
	if len(lines) != 153 {
		t.Errorf("%d\n%s\n%s\n:%s:\n", len(lines), lines[0], lines[1], lines[len(lines)-1])
	}

	header := strings.Split(lines[0], ",")
	if header[6] != "IDM.Family" {
		t.Error("Incorrect header", header[6])
	}
	record := strings.Split(lines[2], ",")
	// SrcPort
	if header[10] != "IDM.SockID.SPort" {
		t.Error("Incorrect header", header[10])
	}
	if record[10] != "9091" {
		t.Error(record[10])
	}
	// SrcIP
	if record[12] != "192.168.14.134" {
		t.Error(record[12])
	}
	// Cookie
	if header[15] != "IDM.SockID.Cookie" {
		t.Error("Incorrect header", header[15])
	}
	if record[15] != "3E8" {
		t.Error(record[15])
	}
}

func TestToCSVFillsInEmptyMetadata(t *testing.T) {
	snap := snapshot.Snapshot{}
	buf := bytes.NewBuffer(nil)
	rtx.Must(toCSV([]*snapshot.Snapshot{&snap}, buf), "Could not convert")
	if snap.Metadata == nil {
		t.Error("Failed to fill in empty metadata")
	}
}
