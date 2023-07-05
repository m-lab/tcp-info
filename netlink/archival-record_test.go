// Package netlink contains the bare minimum needed to partially parse netlink messages.
package netlink

import (
	"testing"
	"unsafe"

	//"github.com/m-lab/go/pretty"

	"github.com/m-lab/tcp-info/inetdiag"
)

func inet2bytes(inet *inetdiag.InetDiagMsg) []byte {
	const sz = int(unsafe.Sizeof(inetdiag.InetDiagMsg{}))
	return (*[sz]byte)(unsafe.Pointer(inet))[:]
}

func TestMakeArchivalRecord(t *testing.T) {
	//fmt.Println(s)
	// ptr := unsafe.Pointer(&inet)
	// (*[len]ArbitraryType)(unsafe.Pointer(ptr))[:]
	// return (*InetDiagMsg)(unsafe.Pointer(&raw[0])), nil
	id := inetdiag.LinuxSockID{
		IDiagSPort: [2]byte{0, 77},          // src port
		IDiagSrc:   [16]byte{127, 0, 0, 1},  // localhost
		IDiagDst:   [16]byte{172, 25, 0, 1}, // dst ip
	}
	tests := []struct {
		name    string
		msg     *NetlinkMessage
		exclude *ExcludeConfig
		want    *ArchivalRecord
		wantErr bool
	}{
		{
			name: "exclude-local",
			msg: &NetlinkMessage{
				Header: NlMsghdr{Type: 20},
				Data:   inet2bytes(&inetdiag.InetDiagMsg{ID: id}),
			},
			exclude: &ExcludeConfig{
				Local: true,
			},
		},
		{
			name: "exclude-srcport",
			msg: &NetlinkMessage{
				Header: NlMsghdr{Type: 20},
				Data:   inet2bytes(&inetdiag.InetDiagMsg{ID: id}),
			},
			exclude: &ExcludeConfig{
				SrcPorts: map[uint16]bool{77: true},
			},
		},
		{
			name: "exclude-dstip",
			msg: &NetlinkMessage{
				Header: NlMsghdr{Type: 20},
				Data:   inet2bytes(&inetdiag.InetDiagMsg{ID: id}),
			},
			exclude: &ExcludeConfig{
				DstIPs: map[[16]byte]bool{[16]byte{172, 25, 0, 1}: true},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// All cases should return nil.
			got, err := MakeArchivalRecord(tt.msg, tt.exclude)
			if err != nil {
				t.Errorf("MakeArchivalRecord() error = %v, wantErr nil", err)
				return
			}
			if got != nil {
				t.Errorf("MakeArchivalRecord() = %v, want nil", got)
			}
		})
	}
	/*
	 */
}
