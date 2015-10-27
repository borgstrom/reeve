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

package protocol

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"time"

	"github.com/borgstrom/reeve/security"
	"github.com/borgstrom/reeve/version"
)

const (
	// Id is used during the protocol announcement -- it is the phonetic representation of Reeve
	Id = "rēv"

	// These are the commands we support
	Ack byte = iota
	Response
	SigningRequest
	TLS
	Director
)

// Protocol represents our own protocol implementation
// Servers & Clients can use this to negotiate a TLS connection or to pass event messages
type Protocol struct {
	conn   net.Conn
	reader *bufio.Reader

	deadline   int
	serverName string
}

// NewProtocol creates a new Protocol instance based on a net.Conn
func NewProtocol(conn net.Conn) *Protocol {
	p := new(Protocol)
	p.conn = conn
	p.setupBuffers()

	// TODO: make this deadline configurable
	p.deadline = 500

	// Set a default server name, this will be replaced with a call to SetServerName
	p.serverName = "reeve-director"

	return p
}

func (p *Protocol) Conn() net.Conn {
	return p.conn
}

func (p *Protocol) setupBuffers() {
	p.reader = bufio.NewReader(p.conn)
}

func (p *Protocol) SetServerName(serverName string) {
	p.serverName = serverName
}

// WriteBytes writes the byte slice
func (p *Protocol) WriteBytes(bytes []byte) error {
	_, err := p.conn.Write(bytes)
	if err != nil {
		return err
	}
	return nil
}

// WriteBytesWithDeadline writes a byte slice with a deadline
func (p *Protocol) WriteBytesWithDeadline(bytes []byte) error {
	p.conn.SetWriteDeadline(time.Now().Add(time.Duration(p.deadline) * time.Millisecond))
	err := p.WriteBytes(bytes)
	p.conn.SetWriteDeadline(time.Time{})
	return err
}

// WriteString writes the string value in s followed by a null byte
func (p *Protocol) WriteString(s string) error {
	return p.WriteBytes([]byte(s + "\x00"))
}

// WriteStringWithDeadline writes the string with a deadline
func (p *Protocol) WriteStringWithDeadline(s string) error {
	p.conn.SetWriteDeadline(time.Now().Add(time.Duration(p.deadline) * time.Millisecond))
	err := p.WriteString(s)
	p.conn.SetWriteDeadline(time.Time{})
	return err
}

// Resp sends an Response
func (p *Protocol) Resp() error {
	return p.WriteBytesWithDeadline([]byte{Response})
}

// Ack sends an Ack
func (p *Protocol) Ack() error {
	return p.WriteBytesWithDeadline([]byte{Ack})
}

// ReadByte reads a single byte and returns it, this is a convenience method for switching
// on protocol commands
func (p *Protocol) ReadByte() (byte, error) {
	buf := make([]byte, 1)
	err := p.ReadBytes(buf)
	return buf[0], err
}

// ReadBytes reads into a byte slice, you must make it yourself first
func (p *Protocol) ReadBytes(bytes []byte) error {
	_, err := p.reader.Read(bytes)
	if err != nil {
		return err
	}
	return nil
}

// ReadBytesWithDeadline reads a string from our connection with the specified deadline
func (p *Protocol) ReadBytesWithDeadline(bytes []byte) error {
	p.conn.SetReadDeadline(time.Now().Add(time.Duration(p.deadline) * time.Millisecond))
	err := p.ReadBytes(bytes)
	p.conn.SetReadDeadline(time.Time{})
	if err != nil {
		return err
	}
	return nil
}

// ReadString reads a string up to a null byte
func (p *Protocol) ReadString() (string, error) {
	bytes, err := p.reader.ReadBytes("\x00"[0])
	if err != nil {
		return "", err
	}

	return string(bytes[0 : len(bytes)-1]), nil
}

// ReadStringWithDeadline reads a string from our connection with the specified deadline
func (p *Protocol) ReadStringWithDeadline() (string, error) {
	p.conn.SetReadDeadline(time.Now().Add(time.Duration(p.deadline) * time.Millisecond))
	str, err := p.ReadString()
	p.conn.SetReadDeadline(time.Time{})
	return str, err
}

func (p *Protocol) tlsSetup(config *tls.Config, identity *security.Identity, caCertificate *security.Certificate) error {
	var (
		certBuf bytes.Buffer
		keyBuf  bytes.Buffer
		err     error
	)

	// We need to prepare our certs & keys for the TLS config
	// Write out our identity certificate and the authority certificate to a single buffer
	identity.Certificate.WritePEM(&certBuf)
	caCertificate.WritePEM(&certBuf)

	// Write the key to the other
	identity.Key.WritePEM(&keyBuf)

	// Load the key pair
	cert, err := tls.X509KeyPair(certBuf.Bytes(), keyBuf.Bytes())
	if err != nil {
		return err
	}

	ca, err := x509.ParseCertificate(cert.Certificate[1])
	if err != nil {
		return err
	}

	// Make our authority certificate as the only item in the pool used for root CAs
	certPool := x509.NewCertPool()
	certPool.AddCert(ca)

	// Update the config
	config.Certificates = []tls.Certificate{cert}
	config.RootCAs = certPool
	config.ClientCAs = certPool

	return nil
}

// StartTLS takes an identity and an authority certificate and upgrades the net.Conn on the protocol to TLS
// It returns the CommonName from the peer certitifcate, or an error
func (p *Protocol) StartTLS(identity *security.Identity, caCertificate *security.Certificate) (string, error) {
	var (
		err     error
		tlsConn *tls.Conn
	)

	if err = p.WriteBytesWithDeadline([]byte{TLS}); err != nil {
		return "", err
	}

	// Build the config
	config := new(tls.Config)
	config.ServerName = p.serverName

	// Setup the tls connection
	if err = p.tlsSetup(config, identity, caCertificate); err != nil {
		return "", err
	}

	// Upgrade the connection to TLS
	// TODO: Add a deadline here?
	tlsConn = tls.Client(p.conn, config)
	if err = tlsConn.Handshake(); err != nil {
		return "", err
	}

	// Capture the connection state
	cs := tlsConn.ConnectionState()

	// And replace the original connection
	p.conn = net.Conn(tlsConn)
	p.setupBuffers()

	return cs.PeerCertificates[0].Subject.CommonName, nil
}

// HandleStartTLS is the companion to StartTLS, and will do the connection upgrade.  It assumes
// that the TLS command byte has already been read.  Like StartTLS it returns the peer name, or
// an error
func (p *Protocol) HandleStartTLS(identity *security.Identity, caCertificate *security.Certificate) (string, error) {
	var (
		err     error
		tlsConn *tls.Conn
	)

	// Build the config
	config := new(tls.Config)
	config.ClientAuth = tls.RequireAndVerifyClientCert

	// Setup the tls connection
	if err := p.tlsSetup(config, identity, caCertificate); err != nil {
		return "", err
	}

	// Upgrade the connection to TLS
	// TODO: Add a deadline here?
	tlsConn = tls.Server(p.conn, config)
	if err = tlsConn.Handshake(); err != nil {
		return "", err
	}

	// Capture the connection state
	cs := tlsConn.ConnectionState()

	// And replace the original connection
	p.conn = net.Conn(tlsConn)
	p.setupBuffers()

	// Send an Ack
	p.Ack()

	return cs.PeerCertificates[0].Subject.CommonName, nil
}

// Announce sends our protocol identifiers over the connection
func (p *Protocol) Announce() error {
	var (
		err error
		buf []byte
	)

	if err = p.WriteStringWithDeadline(Id); err != nil {
		return err
	}
	if err = p.WriteStringWithDeadline(version.ProtocolVersion); err != nil {
		return err
	}

	buf = make([]byte, 1)
	err = p.ReadBytesWithDeadline(buf)
	if err != nil {
		return err
	}
	if buf[0] != Ack {
		return errors.New("Invalid Ack")
	}

	return nil
}

// Validate reads from the connection and makes sure the protocol version being announced is valid
// XXX we should think about how we'll handle the case where you want to do an upgrade between
// XXX protocol versions
func (p *Protocol) Validate() error {
	protoId, err := p.ReadStringWithDeadline()
	if err != nil || protoId != Id {
		return errors.New("Invalid protocol identifier")
	}

	protoVer, err := p.ReadStringWithDeadline()
	if err != nil || protoVer != version.ProtocolVersion {
		return errors.New("Invalid protocol version")
	}

	if err = p.WriteBytesWithDeadline([]byte{Ack}); err != nil {
		return err
	}

	return nil
}

// SendPEMWriter writes the specified pem object and handles the ack
func (p *Protocol) SendPEMWriter(pem security.PEMWriter) error {
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
func (p *Protocol) SendSigningRequest(request *security.Request) error {
	var (
		err error
	)

	if err = p.WriteBytesWithDeadline([]byte{SigningRequest}); err != nil {
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
func (p *Protocol) HandleSigningRequest() (*security.Request, error) {
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
func (p *Protocol) SendCertificate(cert *security.Certificate) error {
	var (
		err error
	)

	if err = p.SendPEMWriter(cert); err != nil {
		return err
	}

	return nil
}

//
func (p *Protocol) HandleCertificate() (*security.Certificate, error) {
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
