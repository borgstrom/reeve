// Reeve director - director
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

package director

import (
	"bytes"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-etcd/etcd"

	log "github.com/Sirupsen/logrus"

	"github.com/borgstrom/reeve/reeve-director/config"
	"github.com/borgstrom/reeve/security"
	"github.com/borgstrom/reeve/server"
)

const (
	heartbeatInterval = 10
)

type Director struct {
	etc      *etcd.Client
	server   *server.Server
	identity *security.Identity
}

func NewDirector() *Director {
	d := new(Director)

	return d
}

func (d Director) CreateIdentity(id string) *security.Identity {
	var caKeys *security.KeyPair

	i := new(security.Identity)

	// load the CA keys
	caKeys = d.LoadKeyPair("/ca")
	if caKeys == nil {
		// Create the CA keys
		// XXX for some reason if we do: caKeys = security.NewCAKeyPair()
		// XXX then accessing caKeys.Cert throws a runtime panic when we call:
		// XXX i.Keys = security.NewKeyPair(...)
		// XXX storing, then re-loading works fine though and since this is a rare
		// XXX occurance I'm leaving this as-is for now.
		d.StoreKeyPair("/ca", security.NewCAKeyPair())
		caKeys = d.LoadKeyPair("/ca")
	}

	i.Id = id
	i.Keys = security.NewKeyPair(id, caKeys.Cert)
	d.StoreKeyPair(config.EtcIdentityPath(id), i.Keys)

	return i
}

func (d Director) LoadIdentity(id string) *security.Identity {
	i := new(security.Identity)

	_, err := d.etc.Get(config.EtcIdentityPath(id), false, false)
	if err != nil {
		// XXX TODO WTF? there has to be a better way to do this
		if err.Error()[0:3] != "100" {
			log.WithFields(log.Fields{
				"error": err,
				"path":  config.EtcIdentityPath(id),
			}).Fatal("Couldn't load identity from etcd")
		}

		// identity doesn't exist
		return nil
	}

	i.Id = id
	i.Keys = d.LoadKeyPair(config.EtcIdentityPath(id))

	return i
}

func (d Director) LoadKeyPair(pathPrefix string) *security.KeyPair {
	keyPath := strings.Join([]string{pathPrefix, "key"}, "/")
	certPath := strings.Join([]string{pathPrefix, "cert"}, "/")

	encodedKey, err := d.etc.Get(keyPath, false, false)
	if err != nil {
		if err.Error()[0:3] != "100" {
			log.WithFields(log.Fields{
				"error": err,
				"path":  keyPath,
			}).Fatal("Couldn't load key from etcd")
		}

		return nil
	}

	encodedCert, err := d.etc.Get(certPath, false, false)
	if err != nil {
		if err.Error()[0:3] != "100" {
			log.WithFields(log.Fields{
				"error": err,
				"path":  certPath,
			}).Fatal("Couldn't load cert from etcd")
		}

		return nil
	}

	return security.LoadKeyPairFromPEM(
		[]byte(encodedKey.Node.Value),
		[]byte(encodedCert.Node.Value),
	)
}

func (d Director) StoreKeyPair(pathPrefix string, keyPair *security.KeyPair) {
	var (
		keyBuf  bytes.Buffer
		certBuf bytes.Buffer
		err     error
	)

	keyPath := strings.Join([]string{pathPrefix, "key"}, "/")
	certPath := strings.Join([]string{pathPrefix, "cert"}, "/")

	keyPair.WriteKey(&keyBuf)
	keyPair.WriteCert(&certBuf)

	_, err = d.etc.Set(keyPath, keyBuf.String(), 0)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"path":  keyPath,
		}).Fatal("Failed to store encoded key")
	}

	_, err = d.etc.Set(certPath, certBuf.String(), 0)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"path":  keyPath,
		}).Fatal("Failed to store encoded certificate")
	}
}

func (d Director) Run() {
	// Connect to etcd
	log.WithFields(log.Fields{
		"hosts": config.ETCD_HOSTS,
	}).Print("Connecting to etcd")
	d.etc = etcd.NewClient(config.ETCD_HOSTS)

	// load our identity
	d.identity = d.LoadIdentity(config.ID)
	if d.identity == nil {
		d.identity = d.CreateIdentity(config.ID)
	}

	// find other directors
	go d.DiscoverDirectors()

	// register as a director
	go d.DirectorHeartbeat()

	// Setup the server
	d.server = server.NewServer(config.HOST, config.PORT)
	go d.server.Listen()

	// block until interrupted
	cleanupChannel := make(chan os.Signal, 1)
	signal.Notify(cleanupChannel, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL)
	<-cleanupChannel
	d.etc.Delete(config.EtcDirectorPath(config.ID), false)
}

func (d Director) DirectorHeartbeat() {
	for {
		if _, err := d.etc.Set(config.EtcDirectorPath(config.ID), "", heartbeatInterval); err != nil {
			log.Fatal(err)
		}
		// sleep for 9.9999999 seconds
		time.Sleep((heartbeatInterval * time.Second) - 1)
	}
}

func (d Director) DiscoverDirectors() {
	log.Print("Discovering other directors")

	updates := make(chan *etcd.Response)

	go func() {
		if _, err := d.etc.Watch(config.EtcDirectorsPath(), 0, true, updates, nil); err != nil {
			log.Fatal(err)
		}
	}()

	for res := range updates {
		parts := strings.Split(res.Node.Key, "/")
		node := parts[2]

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
