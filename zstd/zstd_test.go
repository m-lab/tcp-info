package zstd_test

import (
	"io"
	"io/ioutil"
	"os/exec"
	"testing"

	"github.com/m-lab/tcp-info/zstd"
)

func TestReader(t *testing.T) {
	tmpdir, err := ioutil.TempDir(".", "tmp")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd := exec.Command("rm", "-rf", tmpdir)
		err = cmd.Run()
		if err != nil {
			t.Fatal(err)
		}
	}()

	data := make([]byte, 10000)
	for i := range data {
		data[i] = byte((i * 37) % 256)
	}

	w, wg := zstd.NewWriter(tmpdir + "/test.zst")
	n, err := w.Write(data)
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	wg.Wait()

	read := make([]byte, 20000)
	r := zstd.NewReader(tmpdir + "/test.zst")
	// Interesting...  Sometimes this requires multiple calls to read.
	n, err = io.ReadAtLeast(r, read, 10000)
	if err != nil {
		t.Error(err)
	}
	if n != 10000 {
		t.Error("Wrong number of bytes", n)
	}

	for i := range data {
		if data[i] != read[i] {
			t.Fatal("Data mismatch at", i)
		}
	}
}
