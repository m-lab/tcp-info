package saver_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/tcp-info/metrics"
	"github.com/m-lab/tcp-info/netlink"
	"github.com/m-lab/tcp-info/saver"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
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

type TestMsg struct {
	netlink.NetlinkMessage
}

func (msg *TestMsg) copy() *TestMsg {
	out := TestMsg{}
	out.Header = msg.Header
	copy(out.Data, msg.Data)
	return &out
}

func (msg *TestMsg) setCookie(cookie uint64) *TestMsg {
	raw, _ := inetdiag.SplitInetDiagMsg(msg.Data)
	if raw == nil {
		panic("setCookie failed")
	}
	idm, err := raw.Parse()
	if err != nil {
		panic("setCookie failed")
	}
	for i := 0; i < 8; i++ {
		idm.ID.IDiagCookie[i] = byte(cookie & 0x0FF)
		cookie >>= 8
	}

	return msg
}
func (msg *TestMsg) setDPort(dport uint16) *TestMsg {
	raw, _ := inetdiag.SplitInetDiagMsg(msg.Data)
	if raw == nil {
		panic("setCookie failed")
	}
	idm, err := raw.Parse()
	if err != nil {
		panic("setCookie failed")
	}
	for i := 0; i < 2; i++ {
		idm.ID.IDiagDPort[i] = byte(dport & 0x0FF)
		dport >>= 8
	}

	return msg
}

func (msg *TestMsg) setByte(offset int, value byte) *TestMsg {
	ar, err := netlink.MakeArchivalRecord(&msg.NetlinkMessage, true)
	if err != nil {
		panic("")
	}

	if len(ar.Attributes) <= inetdiag.INET_DIAG_INFO {
		panic("")
	}

	ar.Attributes[inetdiag.INET_DIAG_INFO][offset] = value

	return msg
}

func msg(t *testing.T, cookie uint64, dport uint16) *TestMsg {
	// TODO - this is an incomplete message and should be replaced with a full message.
	var json1 = `{"Header":{"Len":356,"Type":20,"Flags":2,"Seq":1,"Pid":148940},"Data":"CgEAAOpWE6cmIAAAEAMEFbM+nWqBv4ehJgf4sEANDAoAAAAAAAAAgQAAAAAdWwAAAAAAAAAAAAAAAAAAAAAAAAAAAAC13zIBBQAIAAAAAAAFAAUAIAAAAAUABgAgAAAAFAABAAAAAAAAAAAAAAAAAAAAAAAoAAcAAAAAAICiBQAAAAAAALQAAAAAAAAAAAAAAAAAAAAAAAAAAAAArAACAAEAAAAAB3gBQIoDAECcAABEBQAAuAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUCEAAAAAAAAgIQAAQCEAANwFAACsywIAJW8AAIRKAAD///9/CgAAAJQFAAADAAAALMkAAIBwAAAAAAAALnUOAAAAAAD///////////ayBAAAAAAASfQPAAAAAADMEQAANRMAAAAAAABiNQAAxAsAAGMIAABX5AUAAAAAAAoABABjdWJpYwAAAA=="}`
	nm := netlink.NetlinkMessage{}
	err := json.Unmarshal([]byte(json1), &nm)
	if err != nil {
		t.Log(err)
		return nil
	}

	msg := &TestMsg{nm}

	msg = msg.setCookie(cookie).setDPort(dport)
	return msg
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

func histContains(m prometheus.Metric, s string) bool {
	var mm dto.Metric
	m.Write(&mm)
	h := mm.GetHistogram()
	if h == nil {
		log.Println(h)
		return false
	}
	return strings.Contains(h.String(), s)
}

func counterValue(m prometheus.Metric) float64 {
	var mm dto.Metric
	m.Write(&mm)
	ctr := mm.GetCounter()
	if ctr == nil {
		log.Println(mm.GetUntyped())
		return math.Inf(-1)
	}

	return *ctr.Value
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
	svrChan := make(chan netlink.MessageBlock, 0) // no buffering
	go svr.MessageSaverLoop(svrChan)

	date := time.Date(2018, 02, 06, 11, 12, 13, 0, time.UTC)
	mb := netlink.MessageBlock{V4Time: date, V6Time: date}
	// This round just initializes the cache.
	mb.V4Messages = []*netlink.NetlinkMessage{&msg(t, 11234, 11234).NetlinkMessage, &msg(t, 235, 235).NetlinkMessage}
	//dump(t, m1[0])
	svrChan <- mb

	// // This should NOT write to file, because nothing changed
	mb.V4Messages = []*netlink.NetlinkMessage{&msg(t, 1234, 1234).NetlinkMessage, &msg(t, 234, 234).NetlinkMessage}
	svrChan <- mb

	// // This changes the first connection, and ends the second connection.
	mb.V4Messages = []*netlink.NetlinkMessage{&msg(t, 1234, 1234).setByte(20, 127).NetlinkMessage}
	svrChan <- mb

	// // This changes the first connecti:on again.
	mb.V4Messages = []*netlink.NetlinkMessage{&msg(t, 1234, 1234).setByte(20, 127).setByte(105, 127).NetlinkMessage}
	svrChan <- mb

	mb.V4Messages = []*netlink.NetlinkMessage{&msg(t, 1234, 1234).NetlinkMessage}
	svrChan <- mb

	// Force close all the files.
	close(svrChan)
	svr.Done.Wait()

	c := make(chan prometheus.Metric, 10)

	// We should have seen 4 different connections.
	metrics.NewFileCount.Collect(c)
	fc := <-c
	if counterValue(fc) != 4 {
		t.Error("Expected 4, saw ", counterValue(fc))
	}
	close(c)

	// We have to use a range-based size verification because different versions of
	// zstd have slightly different compression ratios.
	// The min/max criteria are based on zstd 1.3.8.
	// These may change with different zstd versions.
	verifySizeBetween(t, 350, 450, "2018/02/06/*_0000000000002BE2.00000.jsonl.zst")
	verifySizeBetween(t, 350, 450, "2018/02/06/*_00000000000000EB.00000.jsonl.zst")
}

// If this compiles, the "test" passes
func assertSaverIsACacheLogger(s *saver.Saver) {
	f := func(csl saver.CacheLogger) {}
	f(s)
}
