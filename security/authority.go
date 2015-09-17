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
	"fmt"
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
		return nil, fmt.Errorf("Failed to generate SubjectKeyId: %s", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		SubjectKeyId: subjectKeyId,

		Subject: pkix.Name{
			CommonName:         "reeve-CA",
			Organization:       []string{"Reeve"},
			OrganizationalUnit: []string{"CA"},
		},

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

	cert, err := CertFromTemplate(template, template, key)
	if err != nil {
		return nil, fmt.Errorf("Failed to create the certificate: %s", err.Error())
	}

	a.Certificate = cert
	a.Key = key
	a.Serial = big.NewInt(2)

	return a, nil
}
