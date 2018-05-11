package cache_test

import (
	"testing"

	"github.com/m-lab/tcp-info/cache"
	"github.com/m-lab/tcp-info/inetdiag"
)

func TestUpdate(t *testing.T) {
	c := cache.NewCache()
	pm1 := inetdiag.ParsedMessage{InetDiagMsg: &inetdiag.InetDiagMsg{IDiagInode: 1234}}
	old := c.Update(&pm1)
	if old != nil {
		t.Error("old should be nil")
	}
	pm2 := inetdiag.ParsedMessage{InetDiagMsg: &inetdiag.InetDiagMsg{IDiagInode: 4321}}
	old = c.Update(&pm2)
	if old != nil {
		t.Error("old should be nil")
	}

	leftover := c.EndCycle()
	if len(leftover) > 0 {
		t.Error("Should be empty")
	}

	pm3 := inetdiag.ParsedMessage{InetDiagMsg: &inetdiag.InetDiagMsg{IDiagInode: 4321}}
	old = c.Update(&pm3)
	if old == nil {
		t.Error("old should NOT be nil")
	}

	leftover = c.EndCycle()
	if len(leftover) != 1 {
		t.Error("Should not be empty")
	}
	for k := range leftover {
		if *leftover[k] != pm1 {
			t.Error("Should have found pm1")
		}
	}
}
