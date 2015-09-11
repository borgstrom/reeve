/*
Reeve - protocol

Copyright 2015 Evan Borgstrom

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*

PROTOCOL TODO / SCRATCH NOTES

Set TLSHandshakeTimeout (http://biasedbit.com/blog/golang-custom-transports/)

*/

package protocol

import (
	"bufio"
	"errors"
	"net"

	log "github.com/Sirupsen/logrus"

	"github.com/borgstrom/reeve/version"
)

const (
	protocolIdentifer = "reeve"
	protocolAck       = "OK"
)

// RawProtocolConn represents our raw unencrypted protocol implementation
// Servers & Clients start with this, then will upgrade it to a TLS connection once the handshake
// and key exchange have been completed
type RawProtocol struct {
	conn   net.Conn
	reader *bufio.Reader
}

func NewRawProtocol(conn net.Conn) *RawProtocol {
	p := new(RawProtocol)
	p.conn = conn
	p.reader = bufio.NewReader(p.conn)
	return p
}

// WriteString writes the string value in s followed by a null byte
func (p RawProtocol) WriteString(s string) error {
	_, err := p.conn.Write([]byte(s + "\x00"))
	if err != nil {
		return err
	}
	return nil
}

// ReadString reads a string up to a null byte
func (p RawProtocol) ReadString() (string, error) {
	bytes, err := p.reader.ReadBytes("\x00"[0])
	if err != nil {
		return "", err
	}

	return string(bytes[0 : len(bytes)-1]), nil
}

// AnnounceProtocol sends our protocol identifiers
func (p RawProtocol) Announce() error {
	var err error
	log.WithFields(log.Fields{
		"addr": p.conn.RemoteAddr(),
	}).Debug("Announcing protocol")

	if err = p.WriteString(protocolIdentifer); err != nil {
		return errors.New("Failed to announce protocol")
	}
	if err = p.WriteString(version.ProtocolVersion); err != nil {
		return errors.New("Failed to announce protocol version")
	}

	resp, err := p.ReadString()
	if err != nil || resp != protocolAck {
		return errors.New("Invalid Ack")
	}

	log.WithFields(log.Fields{
		"addr": p.conn.RemoteAddr(),
	}).Debug("Protocol announced")

	return nil
}

// Validate reads from the connection and makes sure the protocol version being announced is valid
func (p RawProtocol) Validate() error {
	log.WithFields(log.Fields{
		"addr": p.conn.RemoteAddr(),
	}).Debug("Verifying protocol")

	protoId, err := p.ReadString()
	if err != nil || protoId != protocolIdentifer {
		return errors.New("Invalid protocol identifier")
	}

	protoVer, err := p.ReadString()
	if err != nil || protoVer != version.ProtocolVersion {
		return errors.New("Invalid protocol version")
	}

	if err = p.WriteString(protocolAck); err != nil {
		return errors.New("Failed to ack protocol announcement")
	}

	log.WithFields(log.Fields{
		"addr": p.conn.RemoteAddr(),
	}).Debug("Protocol verified")

	return nil
}
