package saver_test

import (
	"encoding/json"
	"log"
	"os"
	"syscall"
	"testing"

	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/tcp-info/saver"
)

// TODO test something!
// Tests:
//   Basic marshaller test.  Simulated data.  Checks filename and size, cleans up.
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

func cleanup(t *testing.T, size int64, filename string) {
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != size {
		t.Error("Size:", info.Size())
	}
	log.Printf("%+v\n", info)
	err = os.Remove(filename)
	info, err = os.Stat(filename)
	if err == nil {
		t.Fatal("Failed to remove file")
	}
}
func TestBasic(t *testing.T) {
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

	// This changes the first connection, and ends the secon connection.
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
	cleanup(t, 271, "00010101Z000000.000U00000000L2620:0:1003:415:b33e:9d6a:81bf:87a1:59990R2607:f8b0:400d:c0a::81:53760_00000.zst")
	cleanup(t, 248, "00010101Z000000.000U00000000L2620:0:1003:415:b33e:9d6a:81bf:87a1:59990R2607:f8b0:400d:c0a::81:59904_00000.zst")
}
