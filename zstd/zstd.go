// Package zstd provides utilities for connecting to external zStandard compression tasks.
package zstd

import (
	"io"
	"log"
	"os"
	"os/exec"
	"sync"

	"github.com/m-lab/go/rtx"
)

// Variables to allow whitebox mocking for testing error conditions.
var (
	osPipe      = os.Pipe
	zstdCommand = "zstd"
)

// NewReader creates a reader piped to external zstd process reading from file.
// This function is only expected to be used for tests, so all errors are fatal.
//
// Users of this function should read from the returned pipe and close it when
// done.
// TODO return errors
func NewReader(filename string) io.ReadCloser {
	pipeR, pipeW, err := osPipe()
	rtx.Must(err, "Could not call os.Pipe. Something is very wrong.")

	cmd := exec.Command(zstdCommand, "-d", "-c", filename)
	cmd.Stdout = pipeW

	f, err := os.Open(filename)
	rtx.Must(err, "Cloud not open file %q for zstd", filename)
	f.Close()

	go func() {
		rtx.Must(cmd.Run(), "ZSTD error for file %q", filename)
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

// NewWriter creates a writer piped to an external zstd process writing to
// filename. It returns a WriteCloser that pipes all writes through a zstd
// compression process. Upon Close(), the returned WriteCloser will wait for the
// zstd process to finish writing to disk.
func NewWriter(filename string) (io.WriteCloser, error) {
	var wg sync.WaitGroup
	wg.Add(1)
	pipeR, pipeW, err := osPipe()
	if err != nil {
		return nil, err
	}
	f, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(zstdCommand)
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
