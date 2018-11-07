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

func TestBasic(t *testing.T) {
	var json1 = `{"Header":{"Len":356,"Type":20,"Flags":2,"Seq":1,"Pid":148940},"Data":"CgEAAOpWE6cmIAAAEAMEFbM+nWqBv4ehJgf4sEANDAoAAAAAAAAAgQAAAAAdWwAAAAAAAAAAAAAAAAAAAAAAAAAAAAC13zIBBQAIAAAAAAAFAAUAIAAAAAUABgAgAAAAFAABAAAAAAAAAAAAAAAAAAAAAAAoAAcAAAAAAICiBQAAAAAAALQAAAAAAAAAAAAAAAAAAAAAAAAAAAAArAACAAEAAAAAB3gBQIoDAECcAABEBQAAuAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUCEAAAAAAAAgIQAAQCEAANwFAACsywIAJW8AAIRKAAD///9/CgAAAJQFAAADAAAALMkAAIBwAAAAAAAALnUOAAAAAAD///////////ayBAAAAAAASfQPAAAAAADMEQAANRMAAAAAAABiNQAAxAsAAGMIAABX5AUAAAAAAAoABABjdWJpYwAAAA=="}`
	nm := syscall.NetlinkMessage{}
	err := json.Unmarshal([]byte(json1), &nm)
	if err != nil {
		t.Fatal(err)
	}
	mp, err := inetdiag.Parse(&nm, true)
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("%+v\n", mp)

	svr := saver.NewSaver("foo", "bar", 1)
	svrChan := make(chan []*inetdiag.ParsedMessage, 0) // no buffering
	go svr.MessageSaverLoop(svrChan)

	messages := []*inetdiag.ParsedMessage{mp}
	// This round just initialized the cache.
	svrChan <- messages

	if len(svr.Connections) != 1 {
		t.Fatal("Connections")
	}

	filename := "00010101Z000000.000U00000000L2620:0:1003:415:b33e:9d6a:81bf:87a1:59990R2607:f8b0:400d:c0a::81:5031_00000.zst"
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}

	// This should NOT write to file, because nothing changed
	//	svrChan <- messages

	mp.Attributes[2].Value[20] += 1
	// This should write to file (through go routine)
	svrChan <- messages

	mp.Attributes[2].Value[105] += 1
	// This should write to file (through go routine)
	svrChan <- messages

	// Force close all the files.
	close(svrChan)
	svr.Done.Wait()

	info, err = os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 250 {
		t.Error("Size:", info.Size())
	}
	log.Printf("%+v\n", info)
	err = os.Remove(filename)
	info, err = os.Stat(filename)
	if err == nil {
		t.Fatal("Failed to remove file")
	}
}
