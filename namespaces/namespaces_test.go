package namespaces_test

import (
	"context"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/namespaces"
)

func makeFakeProc(prefix string) string {
	d, err := ioutil.TempDir("", prefix)
	if err != nil {
		log.Fatal(err)
	}
	// Two PIDs with namespaces.
	rtx.Must(os.MkdirAll(d+"/proc/123/ns/", 0777), "Could not created fake proc")
	rtx.Must(os.Symlink(d+"/proc/123/ns/net:[4026532008]", d+"/proc/123/ns/net"), "Could not create symlink")
	rtx.Must(os.MkdirAll(d+"/proc/456/ns/", 0777), "Could not created fake proc")
	rtx.Must(os.Symlink(d+"/proc/456/ns/net:[4026532010]", d+"/proc/456/ns/net"), "Could not create symlink")
	// One PID with no namespace
	rtx.Must(os.MkdirAll(d+"/proc/789/", 0777), "Could not created fake proc")
	// A bunch of stuff that should never appear in practice.
	rtx.Must(os.MkdirAll(d+"/proc/457/ns/", 0777), "Could not created fake proc")
	rtx.Must(os.Symlink(d+"/proc/457/ns/net:[]", d+"/proc/457/ns/net"), "Could not create symlink")
	rtx.Must(os.MkdirAll(d+"/proc/458/ns/", 0777), "Could not created fake proc")
	rtx.Must(os.Symlink(d+"/proc/458/ns/net[]", d+"/proc/458/ns/net"), "Could not create symlink")
	rtx.Must(os.MkdirAll(d+"/proc/apple/ns/", 0777), "Could not created fake proc")
	rtx.Must(os.Symlink(d+"/proc/apple/ns/net:[4026532010]", d+"/proc/apple/ns/net"), "Could not create symlink")
	rtx.Must(os.MkdirAll(d+"/proc/459/ns/", 0777), "Could not created fake proc")
	rtx.Must(os.Symlink(d+"/proc/459/ns/net:[orange]", d+"/proc/459/ns/net"), "Could not create symlink")
	return d
}

func TestListForeverCancelWorks(t *testing.T) {
	fakeProc := makeFakeProc("TestListForeverCancelWorks")
	log.Println(fakeProc)
	defer os.RemoveAll(fakeProc)

	nsChan := make(chan string)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	go namespaces.WatchForNetworkNamespaces(ctx, fakeProc+"/proc", nsChan)

	ns := make(map[string]struct{})
	for n := range nsChan {
		ns[n] = struct{}{}
	}
	if len(ns) != 2 {
		t.Errorf("Wrong number of namespaces")
	}
}

func TestBadProcFails(t *testing.T) {
	nsChan := make(chan string)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	err := namespaces.WatchForNetworkNamespaces(ctx, "/ThisFileShouldNotExist", nsChan)
	if err != namespaces.ErrCantReadProc {
		t.Error("Should have failed with ErrCantReadProc")
	}
}

func TestProcAsFileFails(t *testing.T) {
	f, err := ioutil.TempFile("", "TestProcAsFileFails")
	if err != nil {
		t.Errorf("Could not make TempFile(%v)", err)
	}
	nsChan := make(chan string)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	err = namespaces.WatchForNetworkNamespaces(ctx, f.Name(), nsChan)
	if err != namespaces.ErrCantReadProc {
		t.Error("Should have failed with ErrCantReadProc")
	}
}
