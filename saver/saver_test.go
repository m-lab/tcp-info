package saver_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/inetdiag"
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

func dump(mp *inetdiag.ParsedMessage) {
	for i := range mp.Attributes {
		a := mp.Attributes[i]
		if a != nil {
			log.Printf("%d %d %+v\n", i, len(a.Value), a)
		}
	}
}

func msg(cookie uint64, dport uint16) *inetdiag.ParsedMessage {
	var json1 = `{"Header":{"Len":356,"Type":20,"Flags":2,"Seq":1,"Pid":148940},"Data":"CgEAAOpWE6cmIAAAEAMEFbM+nWqBv4ehJgf4sEANDAoAAAAAAAAAgQAAAAAdWwAAAAAAAAAAAAAAAAAAAAAAAAAAAAC13zIBBQAIAAAAAAAFAAUAIAAAAAUABgAgAAAAFAABAAAAAAAAAAAAAAAAAAAAAAAoAAcAAAAAAICiBQAAAAAAALQAAAAAAAAAAAAAAAAAAAAAAAAAAAAArAACAAEAAAAAB3gBQIoDAECcAABEBQAAuAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUCEAAAAAAAAgIQAAQCEAANwFAACsywIAJW8AAIRKAAD///9/CgAAAJQFAAADAAAALMkAAIBwAAAAAAAALnUOAAAAAAD///////////ayBAAAAAAASfQPAAAAAADMEQAANRMAAAAAAABiNQAAxAsAAGMIAABX5AUAAAAAAAoABABjdWJpYwAAAA=="}`
	nm := syscall.NetlinkMessage{}
	err := json.Unmarshal([]byte(json1), &nm)
	if err != nil {
		log.Println(err)
		return nil
	}
	mp, err := inetdiag.Parse(&nm, true)
	if err != nil {
		log.Println(err)
		return nil
	}
	for i := 0; i < 8; i++ {
		mp.InetDiagMsg.ID.IDiagCookie[i] = byte(cookie & 0x0FF)
		cookie <<= 8
	}
	for i := 0; i < 2; i++ {
		mp.InetDiagMsg.ID.IDiagDPort[i] = byte(dport & 0x0FF)
		dport <<= 8
	}
	log.Printf("%+v\n", mp)
	return mp
}

func verifySize(t *testing.T, size int64, pattern string) {
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
	if info.Size() != size {
		t.Error("Size of", filename, "is", info.Size(), "but we expect it to be", size)
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
	svrChan := make(chan []*inetdiag.ParsedMessage, 0) // no buffering
	go svr.MessageSaverLoop(svrChan)

	// This round just initializes the cache.
	m1 := []*inetdiag.ParsedMessage{msg(1234, 1234), msg(234, 234)}
	dump(m1[0])
	svrChan <- m1

	// This should NOT write to file, because nothing changed
	m2 := []*inetdiag.ParsedMessage{msg(1234, 1234), msg(234, 234)}
	svrChan <- m2

	// This changes the first connection, and ends the second connection.
	m3 := []*inetdiag.ParsedMessage{msg(1234, 1234)}
	m3[0].Attributes[inetdiag.INET_DIAG_INFO].Value[20] = 127
	svrChan <- m3

	// This changes the first connection again.
	m4 := []*inetdiag.ParsedMessage{msg(1234, 1234)}
	m3[0].Attributes[inetdiag.INET_DIAG_INFO].Value[20] = 127
	m4[0].Attributes[inetdiag.INET_DIAG_INFO].Value[105] = 127
	svrChan <- m4

	m5 := []*inetdiag.ParsedMessage{msg(1234, 1234)}
	svrChan <- m5

	// Force close all the files.
	close(svrChan)
	svr.Done.Wait()
	verifySize(t, 271, "0001/01/01/*_D2.00000.zst")
	verifySize(t, 248, "0001/01/01/*_EA.00000.zst")
}
