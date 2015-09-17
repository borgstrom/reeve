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
	"fmt"
	"net"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/borgstrom/reeve/security"
	"github.com/borgstrom/reeve/version"
)

const (
	Id             = "rēv"
	Ack            = "ack"
	CACertificate  = "ca"
	SigningRequest = "csr"
	SignedCert     = "crt"
	StartTLS       = "tls"
)

// RawProtocolConn represents our raw unencrypted protocol implementation
// Servers & Clients start with this, then will upgrade it to a TLS connection once the handshake
// and key exchange have been completed
type RawProtocol struct {
	conn    net.Conn
	reader  *bufio.Reader
	timeout int
}

// NewRawProtocol creates a new RawProtocol instance based on a net.Conn
func NewRawProtocol(conn net.Conn) *RawProtocol {
	p := new(RawProtocol)
	p.conn = conn
	p.reader = bufio.NewReader(p.conn)

	// TODO: make this timeout configurable
	p.timeout = 100

	return p
}

// WriteString writes the string value in s followed by a null byte
func (p *RawProtocol) WriteString(s string) error {
	p.conn.SetWriteDeadline(time.Now().Add(time.Duration(p.timeout) * time.Millisecond))
	_, err := p.conn.Write([]byte(s + "\x00"))
	if err != nil {
		return err
	}
	return nil
}

// ReadString reads a string up to a null byte
func (p *RawProtocol) ReadString() (string, error) {
	p.conn.SetReadDeadline(time.Now().Add(time.Duration(p.timeout) * time.Millisecond))
	bytes, err := p.reader.ReadBytes("\x00"[0])
	if err != nil {
		return "", err
	}

	return string(bytes[0 : len(bytes)-1]), nil
}

// Announce sends our protocol identifiers over the connection
func (p *RawProtocol) Announce() error {
	var err error
	log.WithFields(log.Fields{
		"address": p.conn.RemoteAddr(),
	}).Debug("Announcing protocol")

	if err = p.WriteString(Id); err != nil {
		return fmt.Errorf("Failed to announce protocol: %s", err.Error())
	}
	if err = p.WriteString(version.ProtocolVersion); err != nil {
		return fmt.Errorf("Failed to announce protocol version: %s", err.Error())
	}

	resp, err := p.ReadString()
	if err != nil {
		return fmt.Errorf("Failed to read Ack: %s", err.Error())
	}
	if resp != Ack {
		return errors.New("Invalid Ack")
	}

	log.WithFields(log.Fields{
		"address": p.conn.RemoteAddr(),
	}).Debug("Protocol announced")

	return nil
}

// Validate reads from the connection and makes sure the protocol version being announced is valid
func (p *RawProtocol) Validate() error {
	log.WithFields(log.Fields{
		"address": p.conn.RemoteAddr(),
	}).Debug("Verifying protocol")

	protoId, err := p.ReadString()
	if err != nil || protoId != Id {
		return errors.New("Invalid protocol identifier")
	}

	protoVer, err := p.ReadString()
	if err != nil || protoVer != version.ProtocolVersion {
		return errors.New("Invalid protocol version")
	}

	if err = p.WriteString(Ack); err != nil {
		return errors.New("Failed to ack protocol announcement")
	}

	log.WithFields(log.Fields{
		"address": p.conn.RemoteAddr(),
	}).Debug("Protocol verified")

	return nil
}

func (p *RawProtocol) SendPEMWriter(pem security.PEMWriter) error {
	var err error

	if err = pem.WritePEM(p.conn); err != nil {
		return fmt.Errorf("Failed to write PEM bytes to the connection: %s", err.Error())
	}
	_, err = p.conn.Write([]byte("\x00"))
	if err != nil {
		return fmt.Errorf("Failed to write PEM trailing null to the connection: %s", err.Error())
	}

	resp, err := p.ReadString()
	if err != nil {
		return fmt.Errorf("Failed to read Ack: %s", err.Error())
	}
	if resp != Ack {
		return errors.New("Invalid Ack")
	}

	return nil
}

// SendSigningRequest sends the Request provided to the director to be signed
func (p *RawProtocol) SendSigningRequest(request *security.Request) error {
	var (
		err error
	)

	if err = p.WriteString(SigningRequest); err != nil {
		return fmt.Errorf("Failed to setup signing request: %s", err.Error())
	}

	if err = p.SendPEMWriter(request); err != nil {
		return fmt.Errorf("Failed to send csr: %s", err.Error())
	}

	return nil
}

// HandleSigningRequest receives a pem encoded message and returns a Request object
// It assumes that the SigningRequest token has already been consumed and the next token is the
// CSR pem bytes
func (p *RawProtocol) HandleSigningRequest() (*security.Request, error) {
	pemRequest, err := p.ReadString()
	if err != nil {
		return nil, fmt.Errorf("Failed to read pem encoded signing request: %s", err)
	}

	request, err := security.RequestFromPEM([]byte(pemRequest))
	if err != nil {
		return nil, fmt.Errorf("Failed to load pem encoded signing request: %s", err)
	}

	if err = p.WriteString(Ack); err != nil {
		return nil, errors.New("Failed to ack signing request")
	}

	return request, nil
}

// SendCACertificate sends a CA certificate as a PEM encoded string
func (p *RawProtocol) SendCACertificate(cert *security.Certificate) error {
	var (
		err error
	)

	if err = p.WriteString(CACertificate); err != nil {
		return fmt.Errorf("Failed to setup CA certificate send: %s", err.Error())
	}

	if err = p.SendPEMWriter(cert); err != nil {
		return fmt.Errorf("Failed to send CA: %s", err.Error())
	}

	return nil
}

// SendCertificate sends a security certificate as a PEM encoded string
func (p *RawProtocol) SendCertificate(cert *security.Certificate) error {
	var (
		err error
	)

	if err = p.WriteString(SignedCert); err != nil {
		return fmt.Errorf("Failed to setup signed certificate send: %s", err.Error())
	}

	if err = p.SendPEMWriter(cert); err != nil {
		return fmt.Errorf("Failed to send crt: %s", err.Error())
	}

	return nil
}

//
func (p *RawProtocol) HandleCertificate() (*security.Certificate, error) {
	pemCert, err := p.ReadString()
	if err != nil {
		return nil, fmt.Errorf("Failed to read pem encoded certificate: %s", err.Error())
	}

	cert, err := security.CertificateFromPEM([]byte(pemCert))
	if err != nil {
		return nil, fmt.Errorf("Failed to load pem coded certificate: %s", err.Error())
	}

	if err = p.WriteString(Ack); err != nil {
		return nil, errors.New("Failed to ack certificate")
	}

	return cert, nil
}
