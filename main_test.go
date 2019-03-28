package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"testing"

	"github.com/m-lab/go/osx"
	"github.com/m-lab/go/rtx"
)

func TestMain(t *testing.T) {
	portFinder, err := net.Listen("tcp", ":0")
	rtx.Must(err, "Could not open server to discover open ports")
	port := portFinder.Addr().(*net.TCPAddr).Port
	portFinder.Close()

	// Write files to a temp directory.
	dir, err := ioutil.TempDir("", "TestMain")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(dir)

	// Make sure that starting up main() does not cause any panics. There's no a
	// lot else we can test, but we can at least make sure that it at least doesn't
	// immediately crash.
	for _, v := range []struct{ name, val string }{
		{"REPS", "1"},
		{"TRACE", "true"},
		{"PROM", fmt.Sprintf(":%d", port)},
		{"OUTPUT", dir},
	} {
		cleanup := osx.MustSetenv(v.name, v.val)
		defer cleanup()
	}

	// REPS=1 should cause main to run once and then exit.
	main()
}
