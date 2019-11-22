package main

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/m-lab/go/osx"
	"github.com/m-lab/go/rtx"
)

func TestMain(t *testing.T) {
	// Write files to a temp directory.
	dir, err := ioutil.TempDir("", "TestMain")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(dir)

	// Make sure that starting up main() does not cause any panics. There's not
	// a lot else we can test, but we can at least make sure that it doesn't
	// immediately crash.
	for _, v := range []struct{ name, val string }{
		{"REPS", "1"},
		{"TRACE", "true"},
		{"OUTPUT", dir},
		{"TCPINFO_EVENTSOCKET", dir + "/eventsock.sock"},
		{"PROMETHEUSX_LISTEN_ADDRESS", ":0"},
	} {
		cleanup := osx.MustSetenv(v.name, v.val)
		defer cleanup()
	}

	// REPS=1 should cause main to run once and then exit.
	main()
}
