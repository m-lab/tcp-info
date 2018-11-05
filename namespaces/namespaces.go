package namespaces

import (
	"context"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

var ErrCantReadProc = errors.New("Can't read /proc")

func WatchForNetworkNamespaces(ctx context.Context, procfs string, nsChan chan<- string) error {
	keepGoing := true
	go func() {
		<-ctx.Done()
		keepGoing = false
	}()
	defer close(nsChan)

	for keepGoing {
		err := listNetworkNamespaces(procfs, nsChan)
		if err != nil {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

func listNetworkNamespaces(procfs string, nsChan chan<- string) error {
	d, err := os.Open(procfs)
	if err != nil {
		return ErrCantReadProc
	}

	subdirs, err := d.Readdirnames(0)
	if err != nil {
		return ErrCantReadProc
	}

	for _, subdir := range subdirs {
		_, err := strconv.Atoi(subdir)
		if err != nil {
			continue
		}
		// Now we know that the subdir of /proc is an int, which means it is a PID.
		// Let us look to see if it contains ns/net
		nsFile, err := os.Readlink(procfs + "/" + subdir + "/ns/net")
		if err != nil {
			// No net namespace for PID.
			continue
		}
		chunks := strings.Split(nsFile, ":")
		if len(chunks) < 2 {
			log.Println("Ill-formatted net namespace:", nsFile)
			continue
		}
		pid := chunks[len(chunks)-1]
		if len(pid) <= 2 {
			log.Println("Namespace has no colon:", nsFile)
			continue
		}
		pid = pid[1 : len(pid)-1]
		_, err = strconv.ParseUint(pid, 10, 64)
		if err != nil {
			log.Println("Namespace is not an integer:", nsFile)
			continue
		}
		nsChan <- pid
	}

	return nil
}
