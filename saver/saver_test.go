package saver_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/tcp-info/netlink"
	"github.com/m-lab/tcp-info/saver"
)

// TODO Tests:
//   File closing.
//   Marshaller selection.
//   Rotation  (use 1 second rotation time)

func init() {
	// Always prepend the filename and line number.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func dump(t *testing.T, mp *netlink.ArchivalRecord) {
	for i := range mp.Attributes {
		a := mp.Attributes[i]
		if a != nil {
			t.Logf("%d %d %+v\n", i, len(a), a)
		}
	}
}

func msg(t *testing.T, cookie uint64, dport uint16) *netlink.ArchivalRecord {
	var json1 = `{"Header":{"Len":356,"Type":20,"Flags":2,"Seq":1,"Pid":148940},"Data":"CgEAAOpWE6cmIAAAEAMEFbM+nWqBv4ehJgf4sEANDAoAAAAAAAAAgQAAAAAdWwAAAAAAAAAAAAAAAAAAAAAAAAAAAAC13zIBBQAIAAAAAAAFAAUAIAAAAAUABgAgAAAAFAABAAAAAAAAAAAAAAAAAAAAAAAoAAcAAAAAAICiBQAAAAAAALQAAAAAAAAAAAAAAAAAAAAAAAAAAAAArAACAAEAAAAAB3gBQIoDAECcAABEBQAAuAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUCEAAAAAAAAgIQAAQCEAANwFAACsywIAJW8AAIRKAAD///9/CgAAAJQFAAADAAAALMkAAIBwAAAAAAAALnUOAAAAAAD///////////ayBAAAAAAASfQPAAAAAADMEQAANRMAAAAAAABiNQAAxAsAAGMIAABX5AUAAAAAAAoABABjdWJpYwAAAA=="}`
	nm := syscall.NetlinkMessage{}
	err := json.Unmarshal([]byte(json1), &nm)
	if err != nil {
		t.Log(err)
		return nil
	}
	mp, err := netlink.MakeArchivalRecord(&nm, true)
	if err != nil {
		t.Log(err)
		return nil
	}
	idm, err := mp.RawIDM.Parse()
	for i := 0; i < 8; i++ {
		idm.ID.IDiagCookie[i] = byte(cookie & 0x0FF)
		cookie >>= 8
	}
	for i := 0; i < 2; i++ {
		idm.ID.IDiagDPort[i] = byte(dport & 0x0FF)
		cookie >>= 8
	}
	t.Logf("%+v\n", mp.RawIDM)
	return mp
}

func verifySizeBetween(t *testing.T, minSize, maxSize int64, pattern string) {
	names, err := filepath.Glob(pattern)
	rtx.Must(err, "Could not Glob pattern %s", pattern)
	if len(names) != 1 {
		t.Fatal("The glob", pattern, "should return exactly one file, not", len(names))
	}
	filename := names[0]
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() < minSize || info.Size() > maxSize {
		_, file, line, _ := runtime.Caller(1)
		t.Error("Size of", filename, " (", info.Size(), ") is out of bounds.  We expect", minSize, "<=", info.Size(), "<=", maxSize, "at", file, line, ".")
	}
}

func TestBasic(t *testing.T) {
	dir, err := ioutil.TempDir("", "tcp-info_saver_TestBasic")
	rtx.Must(err, "Could not create tempdir")
	fmt.Println("Directory is:", dir)
	oldDir, err := os.Getwd()
	rtx.Must(err, "Could not get working directory")
	rtx.Must(os.Chdir(dir), "Could not switch to temp dir %s", dir)
	defer func() {
		os.RemoveAll(dir)
		rtx.Must(os.Chdir(oldDir), "Could not switch back to %s", oldDir)
	}()
	svr := saver.NewSaver("foo", "bar", 1)
	svrChan := make(chan []*netlink.ArchivalRecord, 0) // no buffering
	go svr.MessageSaverLoop(svrChan)

	// This round just initializes the cache.
	m1 := []*netlink.ArchivalRecord{msg(t, 11234, 11234), msg(t, 235, 235)}
	dump(t, m1[0])
	svrChan <- m1

	// This should NOT write to file, because nothing changed
	m2 := []*netlink.ArchivalRecord{msg(t, 1234, 1234), msg(t, 234, 234)}
	svrChan <- m2

	// This changes the first connection, and ends the second connection.
	m3 := []*netlink.ArchivalRecord{msg(t, 1234, 1234)}
	m3[0].Attributes[inetdiag.INET_DIAG_INFO][20] = 127
	svrChan <- m3

	// This changes the first connecti:on again.
	m4 := []*netlink.ArchivalRecord{msg(t, 1234, 1234)}
	m3[0].Attributes[inetdiag.INET_DIAG_INFO][20] = 127
	m4[0].Attributes[inetdiag.INET_DIAG_INFO][105] = 127
	svrChan <- m4

	m5 := []*netlink.ArchivalRecord{msg(t, 1234, 1234)}
	svrChan <- m5
	// Force close all the files.
	close(svrChan)
	svr.Done.Wait()
	// We have to use a range-based size verification because different versions of
	// zstd have slightly different compression ratios.
	// The min/max criteria are based on zstd 1.3.8.
	// These may change with different zstd versions.
	verifySizeBetween(t, 350, 450, "0001/01/01/*_0000000000002BE2.00000.jsonl.zst")
	verifySizeBetween(t, 350, 450, "0001/01/01/*_00000000000000EB.00000.jsonl.zst")
}

// If this compiles, the "test" passes
func assertSaverIsACacheLogger(s *saver.Saver) {
	f := func(csl saver.CacheLogger) {}
	f(s)
}
