package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestFileToCSV(t *testing.T) {
	src := "testdata/ndt-jdczh_1553815964_00000000000003E8.00183.jsonl.zst"
	buf := bytes.NewBuffer(nil)
	err := fileToCSV(src, buf)

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
