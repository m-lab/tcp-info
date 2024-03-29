package cache_test

import (
	"encoding/json"
	"log"
	"testing"

	"github.com/m-lab/tcp-info/cache"
	"github.com/m-lab/tcp-info/netlink"
)

func init() {
	// Always prepend the filename and line number.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func testFatal(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func fakeMsg(t *testing.T, cookie uint64, dport uint16) netlink.ArchivalRecord {
	var json1 = `{"Header":{"Len":356,"Type":20,"Flags":2,"Seq":1,"Pid":148940},"Data":"CgEAAOpWE6cmIAAAEAMEFbM+nWqBv4ehJgf4sEANDAoAAAAAAAAAgQAAAAAdWwAAAAAAAAAAAAAAAAAAAAAAAAAAAAC13zIBBQAIAAAAAAAFAAUAIAAAAAUABgAgAAAAFAABAAAAAAAAAAAAAAAAAAAAAAAoAAcAAAAAAICiBQAAAAAAALQAAAAAAAAAAAAAAAAAAAAAAAAAAAAArAACAAEAAAAAB3gBQIoDAECcAABEBQAAuAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUCEAAAAAAAAgIQAAQCEAANwFAACsywIAJW8AAIRKAAD///9/CgAAAJQFAAADAAAALMkAAIBwAAAAAAAALnUOAAAAAAD///////////ayBAAAAAAASfQPAAAAAADMEQAANRMAAAAAAABiNQAAxAsAAGMIAABX5AUAAAAAAAoABABjdWJpYwAAAA=="}`
	nm := netlink.NetlinkMessage{}
	err := json.Unmarshal([]byte(json1), &nm)
	if err != nil {
		t.Fatal(err)
	}
	mp, err := netlink.MakeArchivalRecord(&nm, &netlink.ExcludeConfig{Local: true})
	if err != nil {
		t.Fatal(err)
	}
	idm, err := mp.RawIDM.Parse()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		idm.ID.IDiagCookie[i] = byte(cookie & 0x0FF)
		cookie >>= 8
	}
	for i := 0; i < 2; i++ {
		idm.ID.IDiagDPort[i] = byte(dport & 0x0FF)
		dport >>= 8
	}
	return *mp
}

func TestUpdate(t *testing.T) {
	c := cache.NewCache()
	pm1 := fakeMsg(t, 0x1234, 1)
	old, err := c.Update(&pm1)
	testFatal(t, err)
	if old != nil {
		t.Error("old should be nil")
	}
	pm2 := fakeMsg(t, 4321, 1)
	old, err = c.Update(&pm2)
	testFatal(t, err)
	if old != nil {
		t.Error("old should be nil")
	}

	if c.CycleCount() != 0 {
		t.Error("CycleCount should be 0, is", c.CycleCount())
	}
	leftover := c.EndCycle()
	if len(leftover) > 0 {
		t.Error("Should be empty")
	}

	pm3 := fakeMsg(t, 4321, 1)
	old, err = c.Update(&pm3)
	testFatal(t, err)
	if old == nil {
		t.Error("old should NOT be nil")
	}

	leftover = c.EndCycle()
	if len(leftover) != 1 {
		t.Error("Should not be empty", len(leftover))
	}
	for k := range leftover {
		if k != 0x1234 {
			t.Errorf("Should have found pm1 %x\n", k)
		}
	}
	if c.CycleCount() != 2 {
		t.Error("CycleCount should be 2, is", c.CycleCount())
	}
}

func TestUpdateWithBadData(t *testing.T) {
	var m netlink.ArchivalRecord
	c := cache.NewCache()
	_, err := c.Update(&m)
	if err == nil {
		t.Error("Should have had an error")
	}
}
