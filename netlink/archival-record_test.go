// Package netlink contains the bare minimum needed to partially parse netlink messages.
package netlink

import (
	"reflect"
	"testing"
	"unsafe"

	"github.com/m-lab/tcp-info/inetdiag"
)

func inet2bytes(inet *inetdiag.InetDiagMsg) []byte {
	const sz = int(unsafe.Sizeof(inetdiag.InetDiagMsg{}))
	return (*[sz]byte)(unsafe.Pointer(inet))[:]
}

func TestMakeArchivalRecord(t *testing.T) {
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
}

func TestExcludeConfig_AddSrcPort(t *testing.T) {
	tests := []struct {
		name      string
		port      string
		wantPorts map[uint16]bool
		wantErr   bool
	}{
		{
			name: "success",
			port: "9999",
			wantPorts: map[uint16]bool{
				9999: true,
			},
		},
		{
			name:    "error",
			port:    "not-a-port",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := &ExcludeConfig{}
			if err := ex.AddSrcPort(tt.port); (err != nil) != tt.wantErr {
				t.Errorf("ExcludeConfig.AddSrcPort() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(ex.SrcPorts, tt.wantPorts) {
				t.Errorf("ExcludeConfig.SrcPorts = %#v, want %#v", ex.SrcPorts, tt.wantPorts)
			}
		})
	}
}

func TestExcludeConfig_AddDstIP(t *testing.T) {
	tests := []struct {
		name    string
		dst     string
		wantIPs map[[16]byte]bool
		wantErr bool
	}{
		{
			name: "success-ipv4",
			dst:  "172.25.0.1",
			wantIPs: map[[16]byte]bool{
				[16]byte{172, 25, 0, 1}: true,
			},
		},
		{
			name: "success-ipv6",
			dst:  "fd0a:008d:ba3f:a834::",
			wantIPs: map[[16]byte]bool{
				[16]byte{0xfd, 0x0a, 0x00, 0x8d, 0xba, 0x3f, 0xa8, 0x34}: true,
			},
		},
		{
			name:    "error",
			dst:     ";not-an-ip;",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := &ExcludeConfig{}
			if err := ex.AddDstIP(tt.dst); (err != nil) != tt.wantErr {
				t.Errorf("ExcludeConfig.AddDstIP() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(ex.DstIPs, tt.wantIPs) {
				t.Errorf("ExcludeConfig.DstIPs = %#v, want %#v", ex.DstIPs, tt.wantIPs)
			}
		})
	}
}
