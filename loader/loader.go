// Package loader contains all logic for reading various file types.
package loader

import (
	"encoding/binary"
	"io"
	"syscall"

	"github.com/m-lab/tcp-info/parse"
)

// LoadNetlinkMessage is a simple utility to read the next NetlinkMessage from a source reader,
// e.g. from a file of naked binary netlink messages.
// NOTE: This is a bit fragile if there are any bit errors in the message headers.
func LoadNetlinkMessage(rdr io.Reader) (*syscall.NetlinkMessage, error) {
	var header syscall.NlMsghdr
	// TODO - should we pass in LittleEndian as a parameter?
	err := binary.Read(rdr, binary.LittleEndian, &header)
	if err != nil {
		// Note that this may be EOF
		return nil, err
	}
	data := make([]byte, header.Len-uint32(binary.Size(header)))
	err = binary.Read(rdr, binary.LittleEndian, data)
	if err != nil {
		return nil, err
	}

	return &syscall.NetlinkMessage{Header: header, Data: data}, nil
}

// LoadParsedMessages reads all PMs from a jsonl stream.
func LoadParsedMessages(rdr io.Reader) ([]*parse.ParsedMessage, error) {
	msgs := make([]*parse.ParsedMessage, 0, 2000) // We typically read a large number of records

	pmr := NewPMReader(rdr)

	for {
		pm, err := pmr.Next()
		if err != nil {
			if err == io.EOF {
				return msgs, nil
			}
			return msgs, err
		}
		msgs = append(msgs, pm)
	}
}

type PMReader struct {
	rdr io.Reader
}

func NewPMReader(rdr io.Reader) *PMReader {
	return &PMReader{rdr: rdr}
}

func (pmr *PMReader) Next() (*parse.ParsedMessage, error) {
	var header syscall.NlMsghdr
	// TODO - should we pass in LittleEndian as a parameter?
	err := binary.Read(pmr.rdr, binary.LittleEndian, &header)
	if err != nil {
		// Note that this may be EOF
		return nil, err
	}
	data := make([]byte, header.Len-uint32(binary.Size(header)))
	err = binary.Read(pmr.rdr, binary.LittleEndian, data)
	if err != nil {
		return nil, err
	}

	msg := syscall.NetlinkMessage{Header: header, Data: data}
	return parse.ParseNetlinkMessage(&msg, false)
}

type InetReader struct {
	pmReader *PMReader
}

func NewInetReader(rdr io.Reader) *InetReader {
	pmr := NewPMReader(rdr)
	return &InetReader{pmReader: pmr}
}

func (r *InetReader) Next() (*parse.Wrapper, error) {
	pm, err := r.pmReader.Next()
	if err != nil {
		return nil, err
	}

	return pm.Decode()
}
