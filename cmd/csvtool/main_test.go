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
	if header[7] != "IDiagFamily" {
		t.Fatal("Incorrect header", header[7])
	}
	if header[11] != "IDiagSPort" {
		t.Fatal("Incorrect header", header[11])
	}
	record := strings.Split(lines[2], ",")
	// SrcPort
	if record[11] != "9091" {
		t.Error(record[11])
	}
	// SrcIP
	if record[13] != "192.168.14.134" {
		t.Error(record[13])
	}
	// Cookie
	if record[16] != "3E8" {
		t.Error(record[15])
	}
}
