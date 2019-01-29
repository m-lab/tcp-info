package uuid_test

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/uuid"
)

func TestUUID(t *testing.T) {
	// We use the less-used TCP versions of Listen and Accept because we want to be
	// sure that we are getting a real TCP connection.
	localAddr, err := net.ResolveTCPAddr("tcp", "localhost:12345")
	rtx.Must(err, "No localhost")
	listener, err := net.ListenTCP("tcp", localAddr)
	rtx.Must(err, "Could not make TCP listener")
	local1, err := net.Dial("tcp", ":12345")
	defer local1.Close()
	local2, err := net.Dial("tcp", ":12345")
	defer local2.Close()
	rtx.Must(err, "Could not connect to myself")
	conn1, err := listener.AcceptTCP()
	rtx.Must(err, "Could not accept conn1")
	conn2, err := listener.AcceptTCP()
	rtx.Must(err, "Could not acceptc conn2")
	uuid1, err := uuid.FromTCPConn(conn1)
	rtx.Must(err, "Could not get uuid for conn1")
	uuid2, err := uuid.FromTCPConn(conn2)
	rtx.Must(err, "Could not get uuid for conn2")
	if uuid1 == uuid2 {
		t.Error("UUIDs must not be the same")
	}
	fmt.Println("UUIDs:", uuid1, uuid2)
	rtx.Must(err, "Could not get uuid")
	left1 := strings.LastIndex(uuid1, "_")
	left2 := strings.LastIndex(uuid2, "_")
	if left1 <= 0 || left2 <= 0 || uuid1[0:left1] != uuid2[0:left2] {
		t.Error("The left part of the UUIDs was not constant:", uuid1, uuid2)
	}
}
