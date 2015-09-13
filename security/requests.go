/*
Reeve - manage certificate requests

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
	"fmt"
	"io"
)

type Request struct {
	*x509.CertificateRequest
}

// NewRequest returns a new x509 signing request based on the provided template
func NewRequest(priv *Key, template *x509.CertificateRequest) (*Request, error) {
	derBytes, err := x509.CreateCertificateRequest(rand.Reader, template, priv.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to create certificate bytes: %s", err.Error())
	}

	csr, err := x509.ParseCertificateRequest(derBytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse certificate bytes: %s", err.Error())
	}

	return &Request{csr}, nil
}

func RequestFromPEM(pemRequest []byte) (*Request, error) {
	requestBlock, _ := pem.Decode(pemRequest)
	if requestBlock == nil {
		return nil, errors.New("Failed to decode request")
	}

	request, err := x509.ParseCertificateRequest(requestBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse request: %s", err.Error())
	}

	return &Request{request}, nil
}

// WritePEM encodes the request using pem and writes it to the provided Writer
func (r Request) WritePEM(buf io.Writer) error {
	err := pem.Encode(buf, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: r.Raw,
	})
	if err != nil {
		return fmt.Errorf("Failed to PEM encode request: %s", err.Error())
	}

	return nil
}
