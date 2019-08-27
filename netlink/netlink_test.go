package netlink_test

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/go-test/deep"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/tcp-info/netlink"
	"github.com/m-lab/tcp-info/tcp"
	"github.com/m-lab/tcp-info/zstd"
)

// This is not exhaustive, but covers the basics.  Integration tests will expose any more subtle
// problems.

func init() {
	// Always prepend the filename and line number.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func TestParse(t *testing.T) {
	var json1 = `{"Header":{"Len":356,"Type":20,"Flags":2,"Seq":1,"Pid":148940},"Data":"CgEAAOpWE6cmIAAAEAMEFbM+nWqBv4ehJgf4sEANDAoAAAAAAAAAgQAAAAAdWwAAAAAAAAAAAAAAAAAAAAAAAAAAAAC13zIBBQAIAAAAAAAFAAUAIAAAAAUABgAgAAAAFAABAAAAAAAAAAAAAAAAAAAAAAAoAAcAAAAAAICiBQAAAAAAALQAAAAAAAAAAAAAAAAAAAAAAAAAAAAArAACAAEAAAAAB3gBQIoDAECcAABEBQAAuAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUCEAAAAAAAAgIQAAQCEAANwFAACsywIAJW8AAIRKAAD///9/CgAAAJQFAAADAAAALMkAAIBwAAAAAAAALnUOAAAAAAD///////////ayBAAAAAAASfQPAAAAAADMEQAANRMAAAAAAABiNQAAxAsAAGMIAABX5AUAAAAAAAoABABjdWJpYwAAAA=="}`
	nm := netlink.NetlinkMessage{}
	err := json.Unmarshal([]byte(json1), &nm)
	t.Log("Data len = ", len(nm.Data))
	rtx.Must(err, "")
	mp, err := netlink.MakeArchivalRecord(&nm, true)
	rtx.Must(err, "")
	idm, err := mp.RawIDM.Parse()
	rtx.Must(err, "")
	// NOTE: darwin unix.AF_INET6 and syscall.AF_INET6 are incorrect (0x1e)!!
	if idm.IDiagFamily != inetdiag.AF_INET6 {
		t.Errorf("IDiagFamily should be IPv6: %d\n %+v\n", idm.IDiagFamily, idm)
	}

	nonNil := 0
	for i := range mp.Attributes {
		if mp.Attributes[i] != nil {
			nonNil++
		}
	}
	if nonNil != 7 {
		t.Error("Incorrect number of attribs")
	}

	if mp.Attributes[inetdiag.INET_DIAG_INFO] == nil {
		t.Error("Should not be nil")
	}

	// TODO: verify that skiplocal actually skips a message when src or dst is 127.0.0.1
}

func TestParseGarbage(t *testing.T) {
	// Json encoding of a good netlink message containing inet diag info.
	var good = `{"Header":{"Len":356,"Type":20,"Flags":2,"Seq":1,"Pid":148940},"Data":"CgEAAOpWE6cmIAAAEAMEFbM+nWqBv4ehJgf4sEANDAoAAAAAAAAAgQAAAAAdWwAAAAAAAAAAAAAAAAAAAAAAAAAAAAC13zIBBQAIAAAAAAAFAAUAIAAAAAUABgAgAAAAFAABAAAAAAAAAAAAAAAAAAAAAAAoAAcAAAAAAICiBQAAAAAAALQAAAAAAAAAAAAAAAAAAAAAAAAAAAAArAACAAEAAAAAB3gBQIoDAECcAABEBQAAuAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUCEAAAAAAAAgIQAAQCEAANwFAACsywIAJW8AAIRKAAD///9/CgAAAJQFAAADAAAALMkAAIBwAAAAAAAALnUOAAAAAAD///////////ayBAAAAAAASfQPAAAAAADMEQAANRMAAAAAAABiNQAAxAsAAGMIAABX5AUAAAAAAAoABABjdWJpYwAAAA=="}`
	nm := netlink.NetlinkMessage{}
	err := json.Unmarshal([]byte(good), &nm)
	if err != nil {
		t.Fatal(err)
	}

	// Truncate the data down to something that makes no sense.
	badNm := nm
	badNm.Data = badNm.Data[:1]
	_, err = netlink.MakeArchivalRecord(&badNm, true)
	if err == nil {
		t.Error("The parse should have failed")
	}

	// Replace the header type with one that we don't support.
	nm.Header.Type = 10
	_, err = netlink.MakeArchivalRecord(&nm, false)
	if err == nil {
		t.Error("Should detect wrong type")
	}

	// Restore the header type.
	nm.Header.Type = 20
	// Replace the payload with garbage.
	for i := range nm.Data {
		// Replace the attribute records with garbage
		nm.Data[i] = byte(i)
	}

	_, err = netlink.MakeArchivalRecord(&nm, false)
	if err == nil || err.Error() != "invalid argument" {
		t.Error(err)
	}

	// Replace length with garbage so that data is incomplete.
	nm.Header.Len = 400
	_, err = netlink.MakeArchivalRecord(&nm, false)
	if err == nil || err.Error() != "invalid argument" {
		t.Error(err)
	}
}
func TestReader(t *testing.T) {
	// Cache info new 140  err 0 same 277 local 789 diff 3 total 1209
	// 1209 sockets 143 remotes 403 per iteration
	source := "testdata/testdata.zst"
	t.Log("Reading messages from", source)
	rdr := zstd.NewReader(source)
	parsed := int64(0)
	for {
		_, err := netlink.LoadRawNetlinkMessage(rdr)
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		parsed++
	}
	if parsed != 420 {
		t.Error("Wrong count:", parsed)
	}
}

func TestCompare(t *testing.T) {
	var json1 = `{"Header":{"Len":356,"Type":20,"Flags":2,"Seq":1,"Pid":148940},"Data":"CgEAAOpWE6cmIAAAEAMEFbM+nWqBv4ehJgf4sEANDAoAAAAAAAAAgQAAAAAdWwAAAAAAAAAAAAAAAAAAAAAAAAAAAAC13zIBBQAIAAAAAAAFAAUAIAAAAAUABgAgAAAAFAABAAAAAAAAAAAAAAAAAAAAAAAoAAcAAAAAAICiBQAAAAAAALQAAAAAAAAAAAAAAAAAAAAAAAAAAAAArAACAAEAAAAAB3gBQIoDAECcAABEBQAAuAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUCEAAAAAAAAgIQAAQCEAANwFAACsywIAJW8AAIRKAAD///9/CgAAAJQFAAADAAAALMkAAIBwAAAAAAAALnUOAAAAAAD///////////ayBAAAAAAASfQPAAAAAADMEQAANRMAAAAAAABiNQAAxAsAAGMIAABX5AUAAAAAAAoABABjdWJpYwAAAA=="}`
	nm := netlink.NetlinkMessage{}
	err := json.Unmarshal([]byte(json1), &nm)
	if err != nil {
		t.Fatal(err)
	}
	mp1, err := netlink.MakeArchivalRecord(&nm, true)
	if err != nil {
		t.Fatal(err)
	}

	// Another independent copy.
	nm2 := netlink.NetlinkMessage{}
	err = json.Unmarshal([]byte(json1), &nm2)
	if err != nil {
		t.Fatal(err)
	}
	mp2, err := netlink.MakeArchivalRecord(&nm2, true)
	if err != nil {
		t.Fatal(err)
	}

	// INET_DIAG_INFO Last... fields should be ignored
	lastDataSentOffset := unsafe.Offsetof(tcp.LinuxTCPInfo{}.LastDataSent)
	pmtuOffset := unsafe.Offsetof(tcp.LinuxTCPInfo{}.PMTU)
	for i := int(lastDataSentOffset); i < int(pmtuOffset); i++ {
		mp2.Attributes[inetdiag.INET_DIAG_INFO][i] += 1
	}
	diff, err := mp1.Compare(mp2)
	rtx.Must(err, "")
	if diff != netlink.NoMajorChange {
		t.Error("Last field changes should not be detected:", deep.Equal(mp1.Attributes[inetdiag.INET_DIAG_INFO],
			mp2.Attributes[inetdiag.INET_DIAG_INFO]))
	}

	// Early parts of INET_DIAG_INFO Should be ignored
	mp2.Attributes[inetdiag.INET_DIAG_INFO][10] = 7
	diff, err = mp1.Compare(mp2)
	rtx.Must(err, "")
	if diff != netlink.StateOrCounterChange {
		t.Error("Early field change not detected:", deep.Equal(mp1.Attributes[inetdiag.INET_DIAG_INFO],
			mp2.Attributes[inetdiag.INET_DIAG_INFO]))
	}

	// packet, segment, and byte counts should NOT be ignored
	mp2.Attributes[inetdiag.INET_DIAG_INFO][pmtuOffset] = 123
	diff, err = mp1.Compare(mp2)
	rtx.Must(err, "")
	if diff != netlink.StateOrCounterChange {
		t.Error("Late field change not detected:", deep.Equal(mp1.Attributes[inetdiag.INET_DIAG_INFO],
			mp2.Attributes[inetdiag.INET_DIAG_INFO]))
	}
}

func TestNLMsgSerialize(t *testing.T) {
	source := "testdata/testdata.zst"
	t.Log("Reading messages from", source)
	rdr := zstd.NewReader(source)
	parsed := 0
	for {
		msg, err := netlink.LoadRawNetlinkMessage(rdr)
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		pm, err := netlink.MakeArchivalRecord(msg, false)
		rtx.Must(err, "Could not parse test data")
		// Parse doesn't fill the Timestamp, so for now, populate it with something...
		pm.Timestamp = time.Date(2009, time.May, 29, 23, 59, 59, 0, time.UTC)

		s, err := json.Marshal(pm)
		rtx.Must(err, "Could not serialize %v", pm)
		if strings.Contains(string(s), "\n") {
			t.Errorf("JSONL object should not contain newline %q", s)
		}
		var um netlink.ArchivalRecord
		rtx.Must(json.Unmarshal([]byte(s), &um), "Could not parse one line of output")
		if diff := deep.Equal(*pm, um); diff != nil {
			// BUG - for some reason, deep.Equal does not detect differences in RTAttr!!!
			t.Error(diff)
		}
		for i := 0; i < len(pm.Attributes); i++ {
			if diff := deep.Equal(pm.Attributes[i], um.Attributes[i]); diff != nil {
				//t.Error(diff)
			}
		}
		if parsed < 3 {
			t.Log(string(s))
			t.Logf("%+v\n", *pm)
		}

		parsed++
	}
	if parsed != 420 {
		t.Error("Wrong count:", parsed)
	}
}

// The bytes/record criterion was determined using zstd 1.3.8.
// These may change with different zstd versions.
func TestCompressionSize(t *testing.T) {
	source := "testdata/testdata.zst"
	srcInfo, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Reading messages from", source)
	rdr := zstd.NewReader(source)
	msgs := make([]*netlink.ArchivalRecord, 0, 200)

	ts := time.Now()

	for {
		msg, err := netlink.LoadRawNetlinkMessage(rdr)
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		pm, err := netlink.MakeArchivalRecord(msg, false)
		pm.Timestamp = ts.Truncate(time.Millisecond).UTC()
		ts = ts.Add(6 * time.Millisecond)
		rtx.Must(err, "Could not parse test data")
		msgs = append(msgs, pm)
	}

	outDir, err := ioutil.TempDir("", "comp")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(outDir)
	fn := outDir + "/comp.zstd"
	w, err := zstd.NewWriter(fn)
	rtx.Must(err, "")
	total := 0
	for _, m := range msgs {
		jsonBytes, err := json.Marshal(m)
		if total < 5 {
			t.Log(string(jsonBytes))
		}
		rtx.Must(err, "Could not serialize %v", m)
		w.Write(jsonBytes)
		total++
	}
	t.Log("Total", total)
	w.Close()
	t.Logf("Raw zstd (no timestamp): %s, %d, %6.1f bytes/record\n", srcInfo.Name(), srcInfo.Size(), float32(srcInfo.Size())/float32(total))
	stats, err := os.Stat(fn)
	rtx.Must(err, "")
	t.Logf("Json zstd: %s, %d, %6.1f bytes/record\n", stats.Name(), stats.Size(), float32(stats.Size())/float32(total))

	// The bytes/record criterion was determined using zstd 1.3.8.
	// These may change with different zstd versions.
	if float32(stats.Size())/float32(total) > 40 {
		t.Errorf("Bytes/Record too large: %6.1f\n", float32(stats.Size())/float32(total))
	}

}

// With []byte representations for most fields, this takes about 3.5 usec/record.
func BenchmarkNLMsgSerialize(b *testing.B) {
	b.StopTimer()
	source := "testdata/testdata.zst"
	b.Log("Reading messages from", source)
	rdr := zstd.NewReader(source)
	msgs := make([]*netlink.ArchivalRecord, 0, 200)

	for {
		msg, err := netlink.LoadRawNetlinkMessage(rdr)
		if err != nil {
			if err == io.EOF {
				break
			}
			b.Fatal(err)
		}
		pm, err := netlink.MakeArchivalRecord(msg, false)
		rtx.Must(err, "Could not parse test data")
		msgs = append(msgs, pm)
	}

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		for _, m := range msgs {
			_, err := json.Marshal(m)
			rtx.Must(err, "Could not serialize %v", m)
			i++
			if i >= b.N {
				break
			}
		}
	}
}

// This takes about 8 usec per record.  zstd process seems to take about 1/3 as much CPU as
// go process.  Not clear where the bottleneck is.  Wall time may not be same as CPU time.
func BenchmarkNLMsgParseSerializeCompress(b *testing.B) {
	b.StopTimer()
	source := "testdata/testdata.zst"
	b.Log("Reading messages from", source)
	rdr := zstd.NewReader(source)
	raw := make([]*netlink.NetlinkMessage, 0, 200)
	msgs := make([]*netlink.ArchivalRecord, 0, 200)

	for {
		msg, err := netlink.LoadRawNetlinkMessage(rdr)
		if err != nil {
			if err == io.EOF {
				break
			}
			b.Fatal(err)
		}
		raw = append(raw, msg)
		pm, err := netlink.MakeArchivalRecord(msg, false)
		rtx.Must(err, "Could not parse test data")
		msgs = append(msgs, pm)
	}

	f, err := ioutil.TempFile("", "TestOneType")
	if err != nil {
		b.Fatal(err)
	}
	name := f.Name()
	os.Remove(name)
	w, _ := zstd.NewWriter(name)
	defer os.Remove(name)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		for _, msg := range raw {
			m, err := netlink.MakeArchivalRecord(msg, false)
			rtx.Must(err, "Could not parse test data")
			jsonBytes, err := json.Marshal(m)
			rtx.Must(err, "Could not serialize %v", m)
			w.Write(jsonBytes)
			i++
			if i >= b.N {
				break
			}
		}
	}
	w.Close()
}

func Test_rawReader_Next(t *testing.T) {
	source := "testdata/testdata.zst"
	t.Log("Reading messages from", source)
	rdr := zstd.NewReader(source)
	defer rdr.Close()
	raw := netlink.NewRawReader(rdr)

	parsed := 0
	for {
		_, err := raw.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		parsed++
	}
	if parsed != 420 {
		t.Error("Wrong count:", parsed)
	}
}

func Test_archiveReader_Next(t *testing.T) {
	source := "testdata/archiveRecords.jsonl.zst"
	log.Println("Reading messages from", source)
	rdr := zstd.NewReader(source)
	defer rdr.Close()
	msgs, err := netlink.LoadAllArchivalRecords(rdr)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 420 {
		t.Error("Wrong count:", len(msgs))
	}
}

func TestGetStats(t *testing.T) {
	source := "testdata/ndt-7hhhv_1559749627_0000000000062D84.00000.jsonl.zst"
	rdr := zstd.NewReader(source)
	defer rdr.Close()
	msgs, err := netlink.LoadAllArchivalRecords(rdr)
	if err != nil {
		t.Fatal(err)
	}
	var s, r uint64
	for i := range msgs {
		if !msgs[i].HasDiagInfo() {
			continue
		}
		ss, rr := msgs[i].GetStats()
		if ss < s || rr < r {
			t.Error(s, ss, r, rr)
		}
		s, r = ss, rr
	}
	// These values can be verified by using the csv tool to dump the ndt-7hhhv_... file, and awking the first and last lines.
	// go run cmd/csvtool/main.go netlink/testdata/ndt-7hhhv_1559749627_0000000000062D84.00000.jsonl.zst | tail -1 | awk -F "," '{print $61, $74}'
	// Confirm the column labels in row 1.
	if s != 3939771 || r != 1245 {
		t.Error(s, r)
	}
}

func TestLoadAllArchivalRecords(t *testing.T) {
	source := "testdata/testdata.zst"
	log.Println("Reading messages from", source)
	rdr := zstd.NewReader(source)
	defer rdr.Close()
	raw := netlink.NewRawReader(rdr)

	parsed := 0
	for {
		_, err := raw.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		parsed++
	}
	if parsed != 420 {
		t.Error("Wrong count:", parsed)
	}
}
