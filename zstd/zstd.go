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
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		// TODO - should return error to caller.
		log.Fatal(err)
	}
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

type waitingWriteCloser struct {
	io.WriteCloser
	wg *sync.WaitGroup
}

func (w waitingWriteCloser) Close() error {
	err := w.WriteCloser.Close()
	if err != nil {
		return err
	}
	w.wg.Wait()
	return nil
}

// NewWriter creates a writer piped to an external zstd process writing to filename
// Write to io.Writer
// close io.Writer when done
// wait on waitgroup to finish
// TODO encapsulate the WaitGroup in a WriteCloser wrapper.
func NewWriter(filename string) (io.WriteCloser, error) {
	var wg sync.WaitGroup
	wg.Add(1)
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	f, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
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

	return waitingWriteCloser{pipeW, &wg}, nil
}
