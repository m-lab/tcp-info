package zstd

import (
	"errors"
	"io/ioutil"
	"os"
	"testing"

	"github.com/m-lab/go/rtx"
)

func TestNewWriterErrorOnOsPipe(t *testing.T) {
	osPipe = func() (*os.File, *os.File, error) {
		return nil, nil, errors.New("Eror for testing")
	}
	defer func() {
		osPipe = os.Pipe
	}()

	_, err := NewWriter("file")
	if err == nil {
		t.Error("Should have had a failure when Pipe fails")
	}
}

func TestNewWriterErrorOnUncreatableFile(t *testing.T) {
	_, err := NewWriter("/this/file/is/uncreateable")
	if err == nil {
		t.Error("Should have had an error on an uncreateable file")
	}
}

func TestZstdFailure(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestZstdFailure")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(dir)

	zstdCommand = "/this/binary/is/nonexistent"
	defer func() {
		zstdCommand = "zstd"
	}()

	wc, err := NewWriter(dir + "/file.zst")
	rtx.Must(err, "WriteCloser could not be created")
	wc.Close()
	err = wc.Close()
	if err == nil {
		t.Error("Closing the pipe twice is not a failure?")
	}
}
