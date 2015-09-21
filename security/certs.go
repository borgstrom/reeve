/*
Reeve - manage certificates

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

package security

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
)

// Certificate is our custom struct that we attach functionality to
type Certificate struct {
	*x509.Certificate
}

// CertificateFromTemplate takes a template, parent, public key & private key and returns a
// composed certificate.  Generally this should be called from an Authority that takes care of
// filling in all of the details from higher level structs.
func CertificateFromTemplate(template *x509.Certificate, parent *x509.Certificate, publicKey interface{}, privateKey *Key) (*Certificate, error) {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey.PrivateKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	return &Certificate{cert}, nil
}

// CertificateFromPEM takes a byte slice that contains a PEM encoded certificate and returns a
// composed Certificate
func CertificateFromPEM(pemCert []byte) (*Certificate, error) {
	certBlock, _ := pem.Decode(pemCert)
	if certBlock == nil {
		return nil, errors.New("Failed to decode cert")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return &Certificate{cert}, nil
}

// WriteCert encodes the x509 certificate using pem and writes it to the provided Writer
func (c *Certificate) WritePEM(buf io.Writer) error {
	err := pem.Encode(buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Raw,
	})
	if err != nil {
		return err
	}

	return nil
}
