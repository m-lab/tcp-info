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
	out.Data = make([]byte, len(msg.Data))
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

func (msg *TestMsg) mustAR() *netlink.ArchivalRecord {
	ar, err := netlink.MakeArchivalRecord(&msg.NetlinkMessage, true)
	if err != nil {
		panic(err)
	}
	if ar == nil {
		panic("nil ar - probably a local connection")
	}

	if len(ar.Attributes) <= inetdiag.INET_DIAG_INFO {
		panic("No INET_DIAG_INFO message")
	}

	return ar
}

func (msg *TestMsg) setByte(offset int, value byte) *TestMsg {
	ar := msg.mustAR()
	ar.Attributes[inetdiag.INET_DIAG_INFO][offset] = value

	return msg
}

func msg(t *testing.T, cookie uint64, dport uint16) *TestMsg {
	// NOTE: If the INET_DIAG_INFO message gets larger, this may cause unit tests to fail, because
	// the TestMsg assumes the message decoding is done in place.
	var json1 = `{"Header":{"Len":420,"Type":20,"Flags":2,"Seq":1,"Pid":235855},"Data":"CgECAIaYE6cmIAAAEAMEFkrF0ry7OloFJgf4sEAMDAYAAAAAAAAAgQAAAABI6AcBAAAAAJgmAAAAAAAAAAAAAAAAAACsINMLBQAIAAAAAAAFAAUAIAAAAAUABgAgAAAAFAABAAAAAAAAAAAAAAAAAAAAAAAoAAcAAAAAAICiBQAAAAAAALQAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5AACAAEAAAAAB3gBYFsDAECcAAB2BQAAGAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2BEAAAAAAACEEQAAyBEAANwFAABAgQAAL0gAACEAAAAHAAAACgAAAJQFAAADAAAAAAAAAIBwAAAAAAAAQdoNAAAAAAD///////////4zAAAAAAAADhAAAAAAAADgAAAA4QAAAAAAAADYRgAAJgAAAC8AAACi4gYAAAAAAGArCwAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAAAAAAAA/TMAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgAEAGN1YmljAAAACAARAAAAAAA="}`
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

func (msg *TestMsg) setBytesSent(value uint64) *TestMsg {
	ar := msg.mustAR()
	ar.SetBytesSent(value)
	return msg
}

func (msg *TestMsg) setBytesReceived(value uint64) *TestMsg {
	ar := msg.mustAR()
	ar.SetBytesReceived(value)
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
	if strings.Contains(h.String(), s) {
		return true
	}
	log.Println("Expected:", s, "Got:", h)
	return false
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

func TestHistograms(t *testing.T) {
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

	// Create basic messages.  These are not internally consistent!!
	m1 := msg(t, 11234, 1).setBytesReceived(0).setBytesSent(0)
	m2 := msg(t, 235, 2).setBytesReceived(1000).setBytesSent(2000)

	// This round just initializes the cache, and causes the first set of rate histogram observations.
	// Sent = 8*2000 = 16000.  Received = 2*1000 = 2000
	mb.V4Messages = []*netlink.NetlinkMessage{&m1.NetlinkMessage, &m2.NetlinkMessage}
	svrChan <- mb

	// This closes the second connection at 401 milliseconds.
	mb.V4Messages = []*netlink.NetlinkMessage{&m1.NetlinkMessage}
	mb.V4Time = mb.V4Time.Add(401 * time.Millisecond)
	svrChan <- mb

	// This modifies the SndMSS field in the first connection.  This causes write to the file, but no stats.
	// TODO - add a snapshot metric?
	m1a := m1.copy().setByte(20, 127)
	mb.V4Messages = []*netlink.NetlinkMessage{&m1a.NetlinkMessage}
	mb.V4Time = mb.V4Time.Add(401 * time.Millisecond)
	svrChan <- mb

	// This changes the first connection again, increasing the BytesReceived (20000) and BytesSent (10000) fields.
	// This also causes the time to roll over a second boundary, and generate stats histogram observations.
	m1b := m1a.copy().setBytesReceived(20000).setBytesSent(10000)
	mb.V4Messages = []*netlink.NetlinkMessage{&m1b.NetlinkMessage}
	mb.V4Time = mb.V4Time.Add(401 * time.Millisecond)
	svrChan <- mb

	m1c := m1b.copy().setBytesSent(100000) // This will be seen only at close channel.
	mb.V4Messages = []*netlink.NetlinkMessage{&m1c.NetlinkMessage}
	mb.V4Time = mb.V4Time.Add(401 * time.Millisecond)
	svrChan <- mb

	// This closes the first connection and rolls over another observation boundary.
	// We should see an observation of 0 Received and 800000 bits Sent.
	mb.V4Messages = []*netlink.NetlinkMessage{}
	mb.V4Time = mb.V4Time.Add(401 * time.Millisecond)
	svrChan <- mb

	// Force close all the files.
	close(svrChan)
	svr.Done.Wait()

	// This section checks that prom metrics are updated appropriately.
	c := make(chan prometheus.Metric, 10)

	// There should have been two updates.  The first update should have been 212944 bits, and
	// the second should have been 0 bits.
	metrics.SendRateHistogram.Collect(c)
	m := <-c
	if !histContains(m, "sample_count:3") {
		t.Error("Wrong sample count")
	}
	if !histContains(m, "sample_sum:816000") { // 2000 bytes + 10000 bytes
		t.Error("Wrong sample sum")
	}

	// The first observation should have 8*2*4110 = 65760 bits.
	// With our tinkering with the setByte(128, 116), we expect the second update to have 25600*8 = 204800 bits.
	// Total then should be 270560
	metrics.ReceiveRateHistogram.Collect(c)
	m = <-c
	if !histContains(m, "sample_count:3") {
		t.Error("Wrong sample count")
	}
	if !histContains(m, "sample_sum:168000") {
		t.Error("Wrong sample sum")
	}

	// For counts in Received, we expect
	// 1 in bucket 0
	// 2 in bucket 10000
	// 3 in bucket 200000
	if !histContains(m, "cumulative_count:2 upper_bound:10000") {
		t.Error("Wrong count for 10000 bucket")
	}
	if !histContains(m, "cumulative_count:3 upper_bound:200000") {
		t.Error("Wrong bucket count for 200000 bucket")
	}

	// We should have seen 2 different connections.
	metrics.NewFileCount.Collect(c)
	fc := <-c
	if counterValue(fc) != 2 {
		t.Error("Expected 2, saw ", counterValue(fc))
	}
	close(c)

	// We have to use a range-based size verification because different versions of
	// zstd have slightly different compression ratios.
	// The min/max criteria are based on zstd 1.3.8.
	// These may change with different zstd versions.
	verifySizeBetween(t, 380, 500, "2018/02/06/*_0000000000002BE2.00000.jsonl.zst")
	verifySizeBetween(t, 350, 450, "2018/02/06/*_00000000000000EB.00000.jsonl.zst")
}

// If this compiles, the "test" passes
func assertSaverIsACacheLogger(s *saver.Saver) {
	f := func(csl saver.CacheLogger) {}
	f(s)
}
