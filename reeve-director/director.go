/*
Reeve director - main code

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

package main

import (
	"bytes"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-etcd/etcd"

	log "github.com/Sirupsen/logrus"

	"github.com/borgstrom/reeve/protocol"
	"github.com/borgstrom/reeve/reeve-director/config"
	"github.com/borgstrom/reeve/security"
)

const (
	heartbeatInterval   = 10
	caIdentity          = "_CA"
	etcDirectorPrefix   = "/directors"
	etcIdentitiesPrefix = "/identities"
)

func etcPath(parts ...string) string {
	return strings.Join(parts, "/")
}

type Director struct {
	etc      *etcd.Client
	server   *protocol.Server
	identity *security.Identity
}

func NewDirector() *Director {
	d := new(Director)

	return d
}

func (d *Director) LoadIdentity(id string) (*security.Identity, error) {
	var (
		pemBytes []byte
		err      error
	)

	etcGet := func(name string) ([]byte, error) {
		resp, err := d.etc.Get(etcPath(etcIdentitiesPrefix, id, name), false, false)
		if err != nil {
			return nil, err
		}

		return []byte(resp.Node.Value), nil
	}

	i := security.NewIdentity(id)

	pemBytes, err = etcGet("key")
	if err != nil {
		if err.Error()[0:3] != "100" {
			return nil, err
		}

		// No key, the identity can't be valid
		return nil, nil
	}
	i.Key, err = security.KeyFromPEM(pemBytes)
	if err != nil {
		return nil, err
	}

	pemBytes, err = etcGet("crt")
	if err != nil {
		if err.Error()[0:3] != "100" {
			return nil, err
		}

		// if there's no certificate see if there's a signing request
		pemBytes, err = etcGet("csr")
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

func (d *Director) StoreIdentity(identity *security.Identity) {
	// etcSet is a closure to handle the repetative task of serializing and setting in etcd
	etcSet := func(name string, pem security.PEMWriter) {
		var (
			pemBuf bytes.Buffer
			err    error
		)
		if err = pem.WritePEM(&pemBuf); err != nil {
			log.WithError(err).Fatal("Failed to write the identity's key to our buffer")
		}
		_, err = d.etc.Set(etcPath(etcIdentitiesPrefix, identity.Id, name), pemBuf.String(), 0)
		if err != nil {
			log.WithError(err).Fatal("Failed to store the identity's encoded key in etcd")
		}
	}

	etcSet("key", identity.Key)

	if identity.Certificate != nil {
		etcSet("crt", identity.Certificate)
	}

	if identity.Request != nil {
		etcSet("csr", identity.Request)
	}
}

func (d *Director) Run() {
	var err error

	// Connect to etcd
	log.WithFields(log.Fields{
		"hosts": config.ETCD_HOSTS,
	}).Info("Connecting to etcd")
	d.etc = etcd.NewClient(config.ETCD_HOSTS)

	// load our identity
	d.identity, err = d.LoadIdentity(config.ID)
	if err != nil {
		log.WithError(err).Fatal("Failed to load our own identity!")
	}
	/*if d.identity == nil {
		d.identity = d.CreateIdentity(config.ID)
	}*/

	// find other directors
	go d.DiscoverDirectors()

	// register as a director
	go d.DirectorHeartbeat()

	// Setup the server
	d.server = protocol.NewServer(config.HOST, config.PORT)
	go d.server.Listen()

	// block until interrupted
	cleanupChannel := make(chan os.Signal, 1)
	signal.Notify(cleanupChannel, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL)
	<-cleanupChannel
	d.etc.Delete(etcPath(etcDirectorPrefix, config.ID), false)
}

func (d *Director) DirectorHeartbeat() {
	for {
		if _, err := d.etc.Set(etcPath(etcDirectorPrefix, config.ID), time.Now().String(), heartbeatInterval); err != nil {
			log.Fatal(err)
		}
		// sleep for 9.9999999 seconds
		time.Sleep((heartbeatInterval * time.Second) - 1)
	}
}

func (d *Director) DiscoverDirectors() {
	log.Print("Discovering other directors")

	updates := make(chan *etcd.Response)

	go func() {
		if _, err := d.etc.Watch(etcDirectorPrefix, 0, true, updates, nil); err != nil {
			log.Fatal(err)
		}
	}()

	for res := range updates {
		parts := strings.Split(res.Node.Key, "/")
		node := parts[len(parts)-1]

		if node == config.ID {
			// ignore events about ourself
			continue
		}

		if res.Action == "set" {
			// check if we know about this director
			log.WithFields(log.Fields{
				"peer": node,
			}).Info("Peer registration")
		}

		if res.Action == "delete" {
			log.WithFields(log.Fields{
				"peer": node,
			}).Info("Peer deletion")
		}

		if res.Action == "expire" {
			log.WithFields(log.Fields{
				"peer": node,
			}).Info("Peer expiration")
		}
	}
}
