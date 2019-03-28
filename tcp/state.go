// Package tcp provides TCP state constants and string coversions for those
// constants.
package tcp

import "fmt"

// State is the enumeration of TCP states.
// https://datatracker.ietf.org/doc/draft-ietf-tcpm-rfc793bis/
// and uapi/linux/tcp.h
type State int32

// All of these constants' names make the linter complain, but we inherited
// these names from external C code, so we will keep them.
const (
	INVALID     State = 0
	ESTABLISHED State = 1
	SYN_SENT    State = 2
	SYN_RECV    State = 3
	FIN_WAIT1   State = 4
	FIN_WAIT2   State = 5
	TIME_WAIT   State = 6
	CLOSE       State = 7
	CLOSE_WAIT  State = 8
	LAST_ACK    State = 9
	LISTEN      State = 10
	CLOSING     State = 11
)

var stateName = map[State]string{
	0:  "INVALID",
	1:  "ESTABLISHED",
	2:  "SYN_SENT",
	3:  "SYN_RECV",
	4:  "FIN_WAIT1",
	5:  "FIN_WAIT2",
	6:  "TIME_WAIT",
	7:  "CLOSE",
	8:  "CLOSE_WAIT",
	9:  "LAST_ACK",
	10: "LISTEN",
	11: "CLOSING",
}

func (x State) String() string {
	s, ok := stateName[x]
	if !ok {
		return fmt.Sprintf("UNKNOWN_STATE_%d", x)
	}
	return s
}
