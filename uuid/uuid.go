package uuid

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	// defined in socket.h in the linux kernel
	syscallSoCookie = 57 // syscall.SO_COOKIE does not exist in golang 1.11
)

var cachedPrefixString = ""

func timeToUnix(t time.Time) int64 {
	return int64(t.Sub(time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)).Seconds())
}

// getBoottimeWithRaceCondition has a race condition between the reading of
// /proc/uptime and the call to time.Now(). If, between those two syscalls, we
// cross a second-granularity time boundary, then the result will be off by one.
// It seems safe to assume, however, that this race condition won't happen twice
// in quick succession, so the recommended way to use this function is to call
// it multiple times until it returns the same answer twice.
func getBoottimeWithRaceCondition() (int64, error) {
	procuptime, err := ioutil.ReadFile("/proc/uptime")
	if err != nil {
		return -1, err
	}
	times := strings.Split(string(procuptime), " ")
	if len(times) != 2 {
		return -1, fmt.Errorf("Could not split /proc/uptime into two parts")
	}
	uptime, err := strconv.ParseFloat(times[0], 64)
	if len(times) != 2 {
		return -1, fmt.Errorf("Could not parse /proc/uptime into a float")
	}
	return timeToUnix(time.Now().Add(time.Duration(-1 * uptime * float64(time.Second)))), nil
}

func getBoottime() (int64, error) {
	// Call the function with the race condition repeatedly until it returns the
	// same answer twice. As long as things take significantly less than a second
	// to run, this will eleiminate the race condition. And if it takes
	// significantly more than a fraction of a second to call time.Now and read
	// /proc/uptime, things are truly messed up.
	var prev, curr int64
	curr, err := getBoottimeWithRaceCondition()
	if err != nil {
		return curr, err
	}
	for prev != curr {
		prev = curr
		curr, err := getBoottimeWithRaceCondition()
		if err != nil {
			return curr, err
		}
	}
	return curr, nil
}

// getPrefix returns a prefix string which contains the hostname and boot time
// of the machine, which globally uniquely identifies the socket uuid namespace.
// This function is cached because that pair should be constant for a given
// instance of the program, unless the boot time changes (how?) or the hostname
// changes (why?) while this program is running.
func getPrefix() (string, error) {
	if cachedPrefixString == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return "", err
		}
		boottime, err := getBoottime()
		if err != nil {
			return "", err
		}
		cachedPrefixString = fmt.Sprintf("%s_%d", hostname, boottime)
	}
	return cachedPrefixString, nil
}

// getCookie returns the cookie (the UUID) associated with a socket. For a given
// boot of a given hostname, this UUID is guaranteed to be unique (until the
// host receives more than 2^64 connections without rebooting).
func getCookie(t *net.TCPConn) (uint64, error) {
	var cookie uint64
	cookieLen := uint32(unsafe.Sizeof(cookie))
	file, err := t.File()
	if err != nil {
		return 0, err
	}
	defer file.Close()
	// GetsockoptInt does not work for 64 bit integers, which is what the UUID is.
	// So we crib from the GetsockoptInt implementation and ndt-server/tcpinfox,
	// and call the syscall manually.
	_, _, errno := syscall.Syscall6(
		uintptr(syscall.SYS_GETSOCKOPT),
		uintptr(int(file.Fd())),
		uintptr(syscall.SOL_SOCKET),
		uintptr(syscallSoCookie),
		uintptr(unsafe.Pointer(&cookie)),
		uintptr(unsafe.Pointer(&cookieLen)),
		uintptr(0))

	if errno != 0 {
		return 0, fmt.Errorf("Error in Getsockopt. Errno=%d", errno)
	}
	return cookie, nil
}

// FromTCPConn returns a string that is a globally unique identifier for the
// socket held by the passed-in TCPConn (assuming hostnames are unique).
func FromTCPConn(t *net.TCPConn) (string, error) {
	cookie, err := getCookie(t)
	if err != nil {
		return "", err
	}
	return FromCookie(cookie)
}

// FromCookie returns a string that is a globally unique identifier for the
// passed-in socket cookie.
func FromCookie(cookie uint64) (string, error) {
	prefix, err := getPrefix()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s_%X", prefix, cookie), nil
}
