/*
Reeve - raw protocol

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
	"time"

	"github.com/borgstrom/reeve/security"
	"github.com/borgstrom/reeve/version"
)

const (
	Id             = "rēv"
	Ack            = "ack"
	Response       = "res"
	SigningRequest = "csr"
	StartTLS       = "tls"
	Director       = "dir"
)

// RawProtocolConn represents our raw unencrypted protocol implementation
// Servers & Clients start with this, then will upgrade it to a TLS connection once the handshake
// and key exchange have been completed
type RawProtocol struct {
	conn   net.Conn
	reader *bufio.Reader

	deadline int
}

// NewRawProtocol creates a new RawProtocol instance based on a net.Conn
func NewRawProtocol(conn net.Conn) *RawProtocol {
	p := new(RawProtocol)
	p.conn = conn
	p.reader = bufio.NewReader(p.conn)

	// TODO: make this deadline configurable
	p.deadline = 500

	return p
}

// WriteString writes the string value in s followed by a null byte
func (p *RawProtocol) WriteString(s string) error {
	_, err := p.conn.Write([]byte(s + "\x00"))
	if err != nil {
		return err
	}
	return nil
}

// WriteStringWithDeadline writes the string with a deadline
func (p *RawProtocol) WriteStringWithDeadline(s string) error {
	p.conn.SetWriteDeadline(time.Now().Add(time.Duration(p.deadline) * time.Millisecond))
	err := p.WriteString(s)
	p.conn.SetWriteDeadline(time.Time{})
	return err
}

// Resp sends an Response
func (p *RawProtocol) Resp() error {
	return p.WriteStringWithDeadline(Response)
}

// Ack sends an Ack
func (p *RawProtocol) Ack() error {
	return p.WriteStringWithDeadline(Ack)
}

// ReadString reads a string up to a null byte
func (p *RawProtocol) ReadString() (string, error) {
	bytes, err := p.reader.ReadBytes("\x00"[0])
	if err != nil {
		return "", err
	}

	return string(bytes[0 : len(bytes)-1]), nil
}

// ReadStringWithDeadline reads a string from our connection with the specified deadline
func (p *RawProtocol) ReadStringWithDeadline() (string, error) {
	p.conn.SetReadDeadline(time.Now().Add(time.Duration(p.deadline) * time.Millisecond))
	str, err := p.ReadString()
	p.conn.SetReadDeadline(time.Time{})
	return str, err
}

// Announce sends our protocol identifiers over the connection
func (p *RawProtocol) Announce() error {
	var err error

	if err = p.WriteStringWithDeadline(Id); err != nil {
		return err
	}
	if err = p.WriteStringWithDeadline(version.ProtocolVersion); err != nil {
		return err
	}

	resp, err := p.ReadStringWithDeadline()
	if err != nil {
		return err
	}
	if resp != Ack {
		return errors.New("Invalid Ack")
	}

	return nil
}

// Validate reads from the connection and makes sure the protocol version being announced is valid
// XXX we should think about how we'll handle the case where you want to do an upgrade between
// XXX protocol versions
func (p *RawProtocol) Validate() error {
	protoId, err := p.ReadStringWithDeadline()
	if err != nil || protoId != Id {
		return errors.New("Invalid protocol identifier")
	}

	protoVer, err := p.ReadStringWithDeadline()
	if err != nil || protoVer != version.ProtocolVersion {
		return errors.New("Invalid protocol version")
	}

	if err = p.WriteStringWithDeadline(Ack); err != nil {
		return err
	}

	return nil
}

// SendPEMWriter writes the specified pem object and handles the ack
func (p *RawProtocol) SendPEMWriter(pem security.PEMWriter) error {
	var err error

	if err = pem.WritePEM(p.conn); err != nil {
		return err
	}
	_, err = p.conn.Write([]byte("\x00"))
	if err != nil {
		return err
	}

	return nil
}

// SendSigningRequest sends the Request provided to the director to be signed
func (p *RawProtocol) SendSigningRequest(request *security.Request) error {
	var (
		err error
	)

	if err = p.WriteStringWithDeadline(SigningRequest); err != nil {
		return err
	}

	if err = p.SendPEMWriter(request); err != nil {
		return err
	}

	return nil
}

// HandleSigningRequest receives a pem encoded message and returns a Request object
// It assumes that the SigningRequest token has already been consumed and the next token is the
// CSR pem bytes
func (p *RawProtocol) HandleSigningRequest() (*security.Request, error) {
	pemRequest, err := p.ReadString()
	if err != nil {
		return nil, err
	}

	request, err := security.RequestFromPEM([]byte(pemRequest))
	if err != nil {
		return nil, err
	}

	return request, nil
}

// SendCertificate sends a security certificate as a PEM encoded string
func (p *RawProtocol) SendCertificate(cert *security.Certificate) error {
	var (
		err error
	)

	if err = p.SendPEMWriter(cert); err != nil {
		return err
	}

	return nil
}

//
func (p *RawProtocol) HandleCertificate() (*security.Certificate, error) {
	var err error

	pemCert, err := p.ReadString()
	if err != nil {
		return nil, err
	}

	cert, err := security.CertificateFromPEM([]byte(pemCert))
	if err != nil {
		return nil, err
	}

	return cert, nil
}
