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
	"os"
	"os/signal"
	"syscall"

	log "github.com/Sirupsen/logrus"

	"github.com/borgstrom/reeve/protocol"
	"github.com/borgstrom/reeve/security"
	"github.com/borgstrom/reeve/state"

	"github.com/borgstrom/reeve/reeve-director/config"
)

const (
	heartbeatInterval = 10
)

type Director struct {
	state     *state.State
	server    *protocol.Server
	identity  *security.Identity
	authority *security.Authority
}

func NewDirector() *Director {
	d := new(Director)

	return d
}

func (d *Director) createCA() {
	var err error

	log.Info("Creating a new Certificate Authority")

	log.Debug("Generating key")
	key, err := security.NewKey()
	if err != nil {
		log.WithError(err).Fatal("Failed to generate CA key")
	}

	log.Debug("Generating certificate")
	d.authority, err = security.NewAuthority(key)
	if err != nil {
		log.WithError(err).Fatal("Failed to generate CA certificate")
	}

	d.state.StoreAuthority(d.authority)
}

func (d *Director) createIdentity(name string) (*security.Identity, error) {
	i := security.NewIdentity(name)

	i.NewKey()

	return i, nil
}

func (d *Director) Run() {
	var err error

	// Create our state
	d.state = state.NewState(config.ETCD_HOSTS)

	// get our authority
	d.authority, err = d.state.LoadAuthority()
	if err != nil {
		log.WithError(err).Fatal("Failed to load CA identity!")
	}
	if d.authority == nil {
		// The CA needs to be setup
		d.createCA()
	}

	// load our identity
	d.identity, err = d.state.LoadIdentity(config.ID)
	if err != nil {
		log.WithError(err).Fatal("Failed to load our own identity!")
	}
	if d.identity == nil {
		d.identity, err = d.createIdentity(config.ID)
		if err != nil {
			log.WithError(err).Fatal("Failed to create our own identity!")
		}
	}

	// find other directors
	directors := make(chan *state.DirectorEvent)
	go func() {
		for event := range directors {
			// We do not want this to be run under another goroutine
			d.HandleDirectorEvent(event)
		}
	}()
	go d.state.DiscoverDirectors(config.ID, directors)

	// register as a director
	go d.state.DirectorHeartbeat(config.ID, heartbeatInterval)

	// Setup the server
	connections := make(chan *protocol.ServerConnection)
	d.server = protocol.NewServer(config.HOST, config.PORT)
	go func() {
		for connection := range connections {
			go d.HandleConnection(connection)
		}
	}()
	go d.server.Listen(connections)

	// block until interrupted
	cleanupChannel := make(chan os.Signal, 1)
	signal.Notify(cleanupChannel, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL)
	<-cleanupChannel
}

func (d *Director) HandleConnection(connection *protocol.ServerConnection) {
	var (
		err      error
		cmd      string
		startTLS bool
	)
	defer connection.Conn.Close()

	// Validate the protocol
	if err = connection.Proto.Validate(); err != nil {
		log.WithError(err).Error("Protocol validation failed")
		return
	}

	// Send the public key of our CA
	if err = connection.Proto.SendCACertificate(d.authority.Certificate); err != nil {
		log.WithError(err).Error("Failed to send CA certificate")
		return
	}

	startTLS = false
	for !startTLS {
		// Read our setup command
		// This will either be a signing request, possibly followed by a tls start, or just a tls start
		cmd, err = connection.Proto.ReadString()
		if err != nil {
			log.WithError(err).Error("TLS setup failed")
			return
		}

		switch cmd {
		case protocol.SigningRequest:
			request, err := connection.Proto.HandleSigningRequest()

			// get the identity via the common name in the request
			identity, err := d.state.LoadIdentity(request.Subject.CommonName)
			if err != nil {
				log.WithFields(log.Fields{
					"error": err,
					"id":    request.Subject.CommonName,
				}).Error("Error while loading the identity")
				return
			}

			if identity == nil {
				// Invalid identity, this means we want to create a new identity for an admin to sign
				identity = security.NewIdentity(request.Subject.CommonName)
				identity.Request = request
				d.state.StoreIdentity(identity)
			} else {
				// See if this identity has a certificate to send back
				if identity.Certificate != nil {
					connection.Proto.SendCertificate(identity.Certificate)
				}
			}

		case protocol.StartTLS:
			startTLS = true
		}
	}

	// Get ready to switch to TLS mode and start RPC & Event Bus
}

func (d *Director) HandleDirectorEvent(event *state.DirectorEvent) {
	if event.Action == "set" {
		// check if we know about this director
		log.WithFields(log.Fields{
			"peer": event.Node,
		}).Info("Peer registration")
	}

	if event.Action == "delete" {
		log.WithFields(log.Fields{
			"peer": event.Node,
		}).Info("Peer deletion")
	}

	if event.Action == "expire" {
		log.WithFields(log.Fields{
			"peer": event.Node,
		}).Info("Peer expiration")
	}
}
