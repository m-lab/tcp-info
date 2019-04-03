package main

import (
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/m-lab/go/rtx"
)

func TestConvertFileToCSV(t *testing.T) {
	stdout := os.Stdout

	r, w, err := os.Pipe()
	rtx.Must(err, "Failed to open pipe: ")
	os.Stdout = w

	wg := sync.WaitGroup{}
	wg.Add(1)
	var readErr error

	go func() {
		readErr = ConvertFileToCSV("testdata/archiveRecords.zst")
		os.Stdout.Close()
		wg.Done()
	}()

	// Must read the output to allow the conversion to proceed.
	output, err := ioutil.ReadAll(r)
	wg.Wait()
	if readErr != nil {
		// This is technically not legal, as testing is not fully threadsafe.
		t.Fatal("Conversion problem", err)
	}

	os.Stdout = stdout

	rtx.Must(err, "Problem reading output")

	lines := strings.Split(string(output), "\n")
	// Split introduces one final empty string, so with the header, the total is 422.
	if len(lines) != 422 {
		t.Errorf("%d\n%s\n%s\n:%s:\n", len(lines), lines[0], lines[1], lines[len(lines)-1])
	}
}

func TestBCNFile(t *testing.T) {
	stdout := os.Stdout

	r, w, err := os.Pipe()
	rtx.Must(err, "Failed to open pipe: ")
	os.Stdout = w

	wg := sync.WaitGroup{}
	wg.Add(1)
	var readErr error

	src := "testdata/bcn01/ndt-jdczh_1553815964_00000000000003E8.00183.jsonl.zst"
	go func() {
		readErr = ConvertFileToCSV(src)
		os.Stdout.Close()
		wg.Done()
	}()

	// Must read the output to allow the conversion to proceed.
	output, err := ioutil.ReadAll(r)
	wg.Wait()
	if readErr != nil {
		// This is technically not legal, as testing is not fully threadsafe.
		t.Fatal("Conversion problem", err)
	}

	os.Stdout = stdout

	rtx.Must(err, "Problem reading output")

	lines := strings.Split(string(output), "\n")
	// Split introduces one final empty string, so with the header, the total is 153.
	if len(lines) != 153 {
		t.Errorf("%d\n%s\n%s\n:%s:\n", len(lines), lines[0], lines[1], lines[len(lines)-1])
	}

}
