/*
Reeve - CA

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
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// Authority holds the CA key, certificate & serial number
// New CAs can be created with the NewAuthority function, otherwise simply create an Authority
// object and assign the attributes using CertificateFromPEM, KeyFromPEM, and your own method
// of storing the serial number (i.e. in etcd)
type Authority struct {
	Key         *Key
	Certificate *Certificate
	Serial      *big.Int
}

// NewAuthority generates a new Authority that is used to sign other Certificates
func NewAuthority(key *Key) (*Authority, error) {
	a := new(Authority)

	subjectKeyId, err := key.GenerateSubjectKeyId()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		SubjectKeyId: subjectKeyId,

		Subject: pkix.Name{
			CommonName:         "reeve-CA",
			Organization:       []string{"Reeve"},
			OrganizationalUnit: []string{"CA"},
		},

		// XXX TODO we are creating certs that have 25 year expiry
		// XXX TODO do we want to make this configurable?
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(25, 0, 0).UTC(),

		IsCA: true,

		BasicConstraintsValid: true,
		MaxPathLen:            0,

		KeyUsage:           x509.KeyUsageCertSign,
		ExtKeyUsage:        nil,
		UnknownExtKeyUsage: nil,

		PermittedDNSDomainsCritical: false,
	}

	cert, err := CertificateFromTemplate(template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}

	a.Certificate = cert
	a.Key = key
	a.Serial = big.NewInt(2)

	return a, nil
}

// Sign takes a Request and returns a signed Certificate
// The Authority data should be locked for this operation to ensure that serial numbers do not
// collide
func (a *Authority) Sign(request *Request) (*Certificate, error) {
	subjectKeyId, err := a.Key.GenerateSubjectKeyId()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: a.Serial,
		SubjectKeyId: subjectKeyId,

		// use the Subject data from the request
		Subject: request.Subject,

		// XXX TODO we are creating certs that have 25 year expiry
		// XXX TODO do we want to make this configurable?
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(25, 0, 0).UTC(),

		KeyUsage: 0,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},

		BasicConstraintsValid:       false,
		PermittedDNSDomainsCritical: false,
	}

	c, err := CertificateFromTemplate(template, a.Certificate.Certificate, request.PublicKey, a.Key)
	if err != nil {
		return nil, err
	}

	// Increment the serial number
	// XXX TODO Does this need to be wrapped in some type of lock so that two directors
	// XXX TODO don't increment at the same time
	a.Serial.Add(a.Serial, big.NewInt(1))

	return c, nil
}
