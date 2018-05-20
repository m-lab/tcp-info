// Package zstd provides utilities for connecting to external zStandard compression tasks.
package zstd

import (
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
)

// NewReader creates a reader piped to external zstd process reading from file.
// Read from returned pipe
// Close pipe when done
func NewReader(filename string) io.ReadCloser {
	pipeR, pipeW, _ := os.Pipe()
	cmd := exec.Command("zstd", "-d", "-c", filename)
	cmd.Stdout = pipeW

	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	f.Close()

	go func() {
		err := cmd.Run()
		if err != nil {
			log.Println("ZSTD error", filename, err)
		}
		pipeW.Close()
	}()

	return pipeR
}

// NewWriter creates a writer piped to an external zstd process writing to filename
// Write to io.Writer
// close io.Writer when done
// wait on waitgroup to finish
// TODO encapsulate the WaitGroup in a WriteCloser wrapper.
func NewWriter(filename string) (io.WriteCloser, *sync.WaitGroup) {
	var wg sync.WaitGroup
	wg.Add(1)
	pipeR, pipeW, _ := os.Pipe()
	f, _ := os.Create(filename)
	cmd := exec.Command("zstd")
	cmd.Stdin = pipeR
	cmd.Stdout = f

	go func() {
		err := cmd.Run()
		if err != nil {
			log.Println("ZSTD error", filename, err)
		}
		pipeR.Close()
		wg.Done()
	}()

	return pipeW, &wg
}
