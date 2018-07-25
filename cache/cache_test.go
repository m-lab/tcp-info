package cache_test

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/m-lab/tcp-info/cache"
	"github.com/m-lab/tcp-info/inetdiag"
)

func fakeMsg(cookie uint64) inetdiag.ParsedMessage {
	pm := inetdiag.ParsedMessage{Timestamp: time.Now(), InetDiagMsg: &inetdiag.InetDiagMsg{}}
	binary.BigEndian.PutUint64(pm.InetDiagMsg.ID.IDiagCookie[:], cookie)
	return pm
}

func TestUpdate(t *testing.T) {
	c := cache.NewCache()
	pm1 := fakeMsg(1234)
	old := c.Update(&pm1)
	if old != nil {
		t.Error("old should be nil")
	}
	pm2 := fakeMsg(4321)
	old = c.Update(&pm2)
	if old != nil {
		t.Error("old should be nil")
	}

	leftover := c.EndCycle()
	if len(leftover) > 0 {
		t.Error("Should be empty")
	}

	pm3 := fakeMsg(4321)
	old = c.Update(&pm3)
	if old == nil {
		t.Error("old should NOT be nil")
	}

	leftover = c.EndCycle()
	if len(leftover) != 1 {
		t.Error("Should not be empty", len(leftover))
	}
	for k := range leftover {
		if *leftover[k] != pm1 {
			t.Error("Should have found pm1")
		}
	}
}
