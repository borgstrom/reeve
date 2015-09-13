/*
Reeve - manage keys

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// Key is our custom type for an ecdsa private key
type Key struct {
	*ecdsa.PrivateKey
}

// NewKey generates a new ecdsa private key
func NewKey() (*Key, error) {
	// TODO: the key size should probably be configurable
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate the private key: %s", err)
	}

	return &Key{priv}, nil
}

// KeyFromPEM returns a Key based on a slice of bytes that represent the PEM encoded version
func KeyFromPEM(pemKey []byte) (*Key, error) {
	keyBlock, _ := pem.Decode(pemKey)
	if keyBlock == nil {
		return nil, errors.New("Failed to decode key")
	}

	priv, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse key: %s", err.Error())
	}

	return &Key{priv}, nil
}

// WritePEM encodes the private key using pem and writes it to the provided Writer
func (k *Key) WritePEM(buf io.Writer) error {
	bytes, err := x509.MarshalECPrivateKey(k.PrivateKey)
	if err != nil {
		return fmt.Errorf("Failed to marshal private key: %s", err.Error())
	}

	err = pem.Encode(buf, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: bytes,
	})
	if err != nil {
		return fmt.Errorf("Failed to PEM encode key: %s", err.Error())
	}

	return nil
}

// keyXY is used when generating SubjectKeyId
type keyXY struct {
	X, Y *big.Int
}

// GenerateSubjectKeyId generates SubjectKeyId used in Certificate
// Id is 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
func (k *Key) GenerateSubjectKeyId() ([]byte, error) {
	pubBytes, err := asn1.Marshal(keyXY{
		X: k.PublicKey.X,
		Y: k.PublicKey.Y,
	})
	if err != nil {
		return nil, err
	}

	hash := sha1.Sum(pubBytes)
	return hash[:], nil
}
