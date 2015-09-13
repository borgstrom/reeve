// Reeve security implementation
//
// Copyright 2015 Evan Borgstrom
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package security

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
)

// PEMWriter is an interface implemented by certs, keys & requests for saving their data in PEM format
type PEMWriter interface {
	WritePEM(buf io.Writer) error
}

// Identity is used to tie a node (Id) to a Key & Certificate, also holding a Request if needed
type Identity struct {
	Id          string
	Key         *Key
	Certificate *Certificate
	Request     *Request
}

// NewIdentity returns a new Identity based on the node ID provided
func NewIdentity(id string) *Identity {
	i := new(Identity)

	i.Id = id

	return i
}

// IsValid returns true if the Identity has a key and a cert or csr
func (i *Identity) IsValid() bool {
	return len(i.Id) > 0 && i.Key != nil && (i.Certificate != nil || i.Request != nil)
}

// IsSigned returns true if the Identity has a certificate
func (i *Identity) IsSigned() bool {
	return len(i.Id) > 0 && i.Key != nil && i.Certificate != nil
}

// Generates a new key for the identity
func (i *Identity) NewKey() error {
	k, err := NewKey()
	if err != nil {
		return err
	}

	i.Key = k
	return nil
}

// Load a key from a PEM encoded form
func (i *Identity) LoadKey(pemBytes []byte) error {
	k, err := KeyFromPEM(pemBytes)
	if err != nil {
		return err
	}

	i.Key = k
	return nil
}

// Generates a new signing request for this identity
func (i *Identity) NewRequest() error {
	if i.Key == nil {
		return errors.New("Identity requires a Key before request can be generated")
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   i.Id,
			Organization: []string{"Reeve"},
		},
		DNSNames: []string{i.Id},
	}

	r, err := NewRequest(i.Key, template)
	if err != nil {
		return err
	}

	i.Request = r
	return nil
}

// Loads a signing request from a PEM encoded form
func (i *Identity) LoadRequest(pemBytes []byte) error {
	r, err := RequestFromPEM(pemBytes)
	if err != nil {
		return err
	}

	i.Request = r
	return nil
}

// Loads a certificate from a PEM encoded form
func (i *Identity) LoadCertificate(certBytes []byte) error {
	c, err := CertificateFromPEM(certBytes)
	if err != nil {
		return err
	}

	i.Certificate = c
	return nil
}
