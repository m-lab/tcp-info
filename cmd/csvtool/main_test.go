package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestFileToCSV(t *testing.T) {
	src := "testdata/bcn01/ndt-jdczh_1553815964_00000000000003E8.00183.jsonl.zst"
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

}
