// Reeve - manage certificates
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"time"

	log "github.com/Sirupsen/logrus"
)

type KeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	Cert       *x509.Certificate
}

func (k KeyPair) WriteKey(buf io.Writer) {
	bytes, err := x509.MarshalECPrivateKey(k.PrivateKey)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Fatal("Failed to marshal private key")
	}

	pem.Encode(buf, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: bytes,
	})
}

func (k KeyPair) WriteCert(buf io.Writer) {
	pem.Encode(buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: k.Cert.Raw,
	})
}

func LoadKeyPairFromPEM(pemKey []byte, pemCert []byte) *KeyPair {
	k := new(KeyPair)

	keyBlock, _ := pem.Decode(pemKey)
	if keyBlock == nil {
		log.WithFields(log.Fields{
			"key": pemKey,
		}).Fatal("Failed to decode key")
	}

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Fatal("Failed to parse key")
	}

	certBlock, _ := pem.Decode(pemCert)
	if certBlock == nil {
		log.WithFields(log.Fields{
			"cert": pemCert,
		}).Fatal("Failed to decode cert")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Fatal("Failed to parse certificate")
	}

	k.PrivateKey = key
	k.Cert = cert

	return k
}

func NewCAKeyPair() *KeyPair {
	k := new(KeyPair)
	k.PrivateKey = makePrivateKey()

	template := makeTemplate("reeve-CA", true)
	k.Cert = makeCertificate(k.PrivateKey, template, template)

	return k
}

func NewKeyPair(id string, parent *x509.Certificate) *KeyPair {
	k := new(KeyPair)
	k.PrivateKey = makePrivateKey()

	template := makeTemplate(id, false)
	k.Cert = makeCertificate(k.PrivateKey, template, parent)

	return k
}

func makeCertificate(priv *ecdsa.PrivateKey, template *x509.Certificate, parent *x509.Certificate) *x509.Certificate {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, &priv.PublicKey, priv)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Fatal("Failed to create certificate bytes")
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Fatal("Failed to parse certificate bytes")
	}

	return cert
}

func makePrivateKey() *ecdsa.PrivateKey {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Fatal("Failed to generate the private key")
	}
	return priv
}

func makeTemplate(id string, isCA bool) *x509.Certificate {
	// the cert will be valid for 10 years
	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Fatal("Failed to generate a serial number")
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   id,
			Organization: []string{"Reeve"},
		},
		DNSNames: []string{id},

		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if isCA == true {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	return &template
}
