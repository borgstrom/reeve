/*
Reeve director - state implementation

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

package state

import (
	"bytes"
	"math/big"
	"strconv"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/coreos/go-etcd/etcd"

	"github.com/borgstrom/reeve/security"
)

const (
	etcDirectorPrefix   = "/directors"
	etcIdentitiesPrefix = "/identities"
	etcAuthorityPrefix  = "/authority"
)

func etcPath(parts ...string) string {
	return strings.Join(parts, "/")
}

type DirectorEvent struct {
	Action string
	Node   string
}

type State struct {
	etc *etcd.Client
}

// NewState creates a new state object and connects to the specified etc hosts
func NewState(etcHosts []string) *State {
	s := new(State)

	log.WithFields(log.Fields{
		"hosts": etcHosts,
	}).Info("Connecting to etcd")
	s.etc = etcd.NewClient(etcHosts)

	return s
}

// setPEM stores a security PEM Writer in the state
func (s *State) setPEM(path string, pem security.PEMWriter) error {
	var (
		pemBuf bytes.Buffer
		err    error
	)
	if err = pem.WritePEM(&pemBuf); err != nil {
		return err
	}

	_, err = s.etc.Set(path, pemBuf.String(), 0)
	if err != nil {
		return err
	}

	return nil
}

// getBytes fetchs a value and returns it as a byte slice
func (s *State) getBytes(path string) ([]byte, error) {
	resp, err := s.etc.Get(path, false, false)
	if err != nil {
		return nil, err
	}

	return []byte(resp.Node.Value), nil
}

// DirectorHeartbeat is a simple function that sets a key with our ID every heartbeatInterval
func (s *State) DirectorHeartbeat(id string, interval uint64) {
	for {
		if _, err := s.etc.Set(etcPath(etcDirectorPrefix, id), time.Now().String(), interval); err != nil {
			log.WithFields(log.Fields{
				"error":    err,
				"id":       id,
				"interval": interval,
			}).Fatal("Failed to set director heartbeat!")
		}

		// sleep for 9.9999999 seconds
		time.Sleep(time.Duration(interval)*time.Second - 1)
	}
}

// DiscoverDirectors
func (s *State) DiscoverDirectors(localId string, events chan *DirectorEvent) {
	log.Print("Discovering other directors")

	updates := make(chan *etcd.Response)

	go func() {
		if _, err := s.etc.Watch(etcDirectorPrefix, 0, true, updates, nil); err != nil {
			log.WithError(err).Fatal("Failed to watch etc director prefix")
		}
	}()

	for res := range updates {
		parts := strings.Split(res.Node.Key, "/")
		node := parts[len(parts)-1]

		if node == localId {
			// ignore events about ourself
			continue
		}

		events <- &DirectorEvent{
			Action: res.Action,
			Node:   node,
		}
	}
}

// LoadIdentity loads the identity with the id specified
func (s *State) LoadIdentity(id string) (*security.Identity, error) {
	var (
		pemBytes []byte
		err      error
	)

	i := security.NewIdentity(id)

	pemBytes, err = s.getBytes(etcPath(etcIdentitiesPrefix, id, "key"))
	if err != nil {
		if err.Error()[0:3] != "100" {
			return nil, err
		}
	} else {
		i.Key, err = security.KeyFromPEM(pemBytes)
		if err != nil {
			return nil, err
		}
	}

	pemBytes, err = s.getBytes(etcPath(etcIdentitiesPrefix, id, "crt"))
	if err != nil {
		if err.Error()[0:3] != "100" {
			return nil, err
		}

		// if there's no certificate see if there's a signing request
		pemBytes, err = s.getBytes(etcPath(etcIdentitiesPrefix, id, "csr"))
		if err != nil {
			if err.Error()[0:3] != "100" {
				return nil, err
			}
		} else {
			i.Request, err = security.RequestFromPEM(pemBytes)
			if err != nil {
				return nil, err
			}
		}
	} else {
		i.Certificate, err = security.CertificateFromPEM(pemBytes)
		if err != nil {
			return nil, err
		}
	}

	// Now check the validitiy of the identity
	if !i.IsValid() {
		return nil, nil
	}

	return i, nil
}

// StoreIdentity stores the specified identity in etcd
func (s *State) StoreIdentity(identity *security.Identity) {
	if identity.Key != nil {
		s.setPEM(etcPath(etcIdentitiesPrefix, identity.Id, "key"), identity.Key)
	}

	if identity.Certificate != nil {
		s.setPEM(etcPath(etcIdentitiesPrefix, identity.Id, "crt"), identity.Certificate)
	}

	if identity.Request != nil {
		s.setPEM(etcPath(etcIdentitiesPrefix, identity.Id, "csr"), identity.Request)
	}
}

// LoadAuthority fetches the authority information
func (s *State) LoadAuthority() (*security.Authority, error) {
	var (
		pemBytes []byte
		err      error
		key      *security.Key
		cert     *security.Certificate
	)

	pemBytes, err = s.getBytes(etcPath(etcAuthorityPrefix, "key"))
	if err != nil {
		if err.Error()[0:3] != "100" {
			return nil, err
		} else {
			return nil, nil
		}
	} else {
		key, err = security.KeyFromPEM(pemBytes)
		if err != nil {
			return nil, err
		}
	}

	pemBytes, err = s.getBytes(etcPath(etcAuthorityPrefix, "crt"))
	if err != nil {
		if err.Error()[0:3] != "100" {
			return nil, err
		} else {
			return nil, nil
		}
	} else {
		cert, err = security.CertificateFromPEM(pemBytes)
		if err != nil {
			return nil, err
		}
	}

	// Load the serial number
	resp, err := s.etc.Get(etcPath(etcAuthorityPrefix, "serial"), false, false)
	if err != nil {
		return nil, err
	}
	serial, err := strconv.ParseInt(resp.Node.Value, 10, 64)
	if err != nil {
		return nil, err
	}

	return &security.Authority{
		Key:         key,
		Certificate: cert,
		Serial:      big.NewInt(serial),
	}, nil
}

func (s *State) StoreAuthority(authority *security.Authority) {
	var err error

	if err = s.setPEM(etcPath(etcAuthorityPrefix, "key"), authority.Key); err != nil {
		log.WithError(err).Fatal("Failed to store authority key")
	}
	if err = s.setPEM(etcPath(etcAuthorityPrefix, "crt"), authority.Certificate); err != nil {
		log.WithError(err).Fatal("Failed to store authority certificate")
	}

	s.StoreAuthoritySerial(authority)
}

func (s *State) StoreAuthoritySerial(authority *security.Authority) {
	_, err := s.etc.Set(etcPath(etcAuthorityPrefix, "serial"), authority.Serial.String(), 0)
	if err != nil {
		log.WithError(err).Fatal("Failed to store authority serial")
	}
}
