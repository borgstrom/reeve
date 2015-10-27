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
	"net"
	"os"
	"os/signal"
	"syscall"

	log "github.com/Sirupsen/logrus"

	"github.com/borgstrom/reeve/eventbus"
	"github.com/borgstrom/reeve/modules"
	"github.com/borgstrom/reeve/protocol"
	"github.com/borgstrom/reeve/reeve-director/config"
	"github.com/borgstrom/reeve/rpc/command"
	"github.com/borgstrom/reeve/rpc/control"
	"github.com/borgstrom/reeve/security"
	"github.com/borgstrom/reeve/state"
)

const (
	heartbeatInterval = 10
)

// Director holds all of the state
type Director struct {
	state         *state.State
	commandServer *protocol.Server
	controlServer *protocol.Server
	identity      *security.Identity
	authority     *security.Authority
	bus           *eventbus.EventBus
	agents        map[string]*Agent
}

// Agent holds ...
type Agent struct {
	id       string
	identity *security.Identity
	command  *command.CommandClient
	commands chan *command.DispatchRequest
}

// NewDirector returns a new Director
func NewDirector(etcHosts []string, controlAddress string, commandAddress string) *Director {
	d := new(Director)

	d.agents = make(map[string]*Agent)

	// Create our state
	d.state = state.NewState(etcHosts)

	// Setup the servers
	d.controlServer = protocol.NewServer(controlAddress)
	d.commandServer = protocol.NewServer(commandAddress)

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

	log.WithFields(log.Fields{
		"name": name,
	}).Info("Creating new identity")

	i.NewKey()
	i.NewRequest()

	return i, nil
}

func (d *Director) Run(id string) {
	var err error

	// get our authority
	log.Info("Loading authority")
	d.authority, err = d.state.LoadAuthority()
	if err != nil {
		log.WithError(err).Fatal("Failed to load CA identity!")
	}
	if d.authority == nil {
		// The CA needs to be setup
		d.createCA()
	}

	// load our identity
	log.Info("Loading identity")
	d.identity, err = d.state.LoadIdentity(config.ID())
	if err != nil {
		log.WithError(err).Fatal("Failed to load our own identity!")
	}
	if d.identity == nil {
		d.identity, err = d.createIdentity(config.ID())
		if err != nil {
			log.WithError(err).Fatal("Failed to create our own identity!")
		}

		// Now sign the identity, to get back a completed certificate
		cert, err := d.authority.Sign(d.identity.Request)
		if err != nil {
			log.WithError(err).Fatal("Failed to sign our own request!")
		}

		// Associate the certificate
		d.identity.Certificate = cert

		// Store our identity
		d.state.StoreIdentity(d.identity)
	}

	// Setup the event bus
	d.bus = eventbus.NewEventBus()

	// find other directors
	directors := make(chan *state.DirectorEvent)
	go func() {
		for event := range directors {
			// We do not want this to be run under another goroutine
			d.HandleDirectorEvent(event)
		}
	}()
	go d.state.DiscoverDirectors(config.ID(), directors)

	// register as a director
	go d.state.DirectorHeartbeat(config.ID(), heartbeatInterval)

	// watch for agent expirations
	// XXX TODO

	// Start our servers listening
	log.WithFields(log.Fields{
		"server": d.controlServer,
	}).Debug("Listening for control connections")
	go d.controlServer.Listen(d.HandleControlConnection)

	log.WithFields(log.Fields{
		"server": d.commandServer,
	}).Debug("Listening for command connections")
	go d.commandServer.Listen(d.HandleCommandConnection)

	// block until interrupted
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL)
	sigReceived := <-sig
	log.WithFields(log.Fields{"signal": sigReceived}).Info("Received signal")
}

// HandleControlConnection ...
func (d *Director) HandleControlConnection(conn net.Conn) {
	var (
		err      error
		cmd      byte
		peerId   string
		startTLS bool
	)
	defer conn.Close()

	// setup a base logger so all messages include our address
	logger := log.WithFields(log.Fields{
		"address": conn.RemoteAddr().String(),
		"type":    "control",
	})

	logger.Debug("New connection for Control RPC")

	proto := protocol.NewProtocol(conn)

	// Announce the protocol
	logger.Debug("Announcing protocol")
	if err = proto.Announce(); err != nil {
		log.WithError(err).Error("Protocol announcement failed")
		return
	}
	logger.Debug("Protocol announced")

	logger.Debug("Beginning TLS setup")
	startTLS = false
	for !startTLS {
		cmd, err = proto.ReadByte()
		if err != nil {
			logger.WithError(err).Error("Failed to read protocol command")
			return
		}

		switch cmd {
		case protocol.SigningRequest:
			logger.Debug("Reading signing request")
			request, err := proto.HandleSigningRequest()
			if err != nil {
				logger.WithError(err).Error("Failed to read signing request")
				return
			}

			// get the identity via the common name in the request
			logger.WithFields(log.Fields{
				"name": request.Subject.CommonName,
			}).Debug("Loading identity")

			identity, err := d.state.LoadIdentity(request.Subject.CommonName)
			if err != nil {
				logger.WithFields(log.Fields{
					"error": err,
					"id":    request.Subject.CommonName,
				}).Error("Error while loading the identity")
				return
			}

			if identity == nil {
				// Invalid identity, this means we want to create a new identity for an admin to sign
				logger.WithFields(log.Fields{
					"name": request.Subject.CommonName,
				}).Debug("Creating new identity")

				identity = security.NewIdentity(request.Subject.CommonName)
				identity.Request = request
				d.state.StoreIdentity(identity)
				d.state.AddIdentityToPending(identity)

				if err = proto.Ack(); err != nil {
					logger.WithError(err).Error("Failed to ack signing request")
					return
				}
			} else {
				// See if this identity has a certificate to send back
				if identity.Certificate != nil {
					logger.WithFields(log.Fields{
						"name": request.Subject.CommonName,
					}).Debug("Sending signed certificate")

					if err = proto.Resp(); err != nil {
						logger.WithError(err).Error("Failed to signal response")
						return
					}

					proto.SendCertificate(identity.Certificate)
					proto.SendCertificate(d.authority.Certificate)
				} else {
					if err = proto.Ack(); err != nil {
						logger.WithError(err).Error("Failed to ack signing request")
						return
					}

					logger.WithFields(log.Fields{
						"name": request.Subject.CommonName,
					}).Debug("Request is still pending")
				}
			}

		case protocol.TLS:
			logger.Info("Upgrading connection to TLS")
			if peerId, err = proto.HandleStartTLS(d.identity, d.authority.Certificate); err != nil {
				logger.WithError(err).Error("Failed up handle Start TLS")
				return
			}
			logger.WithFields(log.Fields{
				"peerId": peerId,
			}).Debug("Upgraded!")

			// Load our identity.   We don't actually care about the identity -- we just want to
			// make sure that it's valid and loads correctly based on this peer ID
			_, err := d.state.LoadIdentity(peerId)
			if err != nil {
				logger.WithError(err).Error("Failed to load Agent Identity")
				return
			}

			startTLS = true

		default:
			logger.WithFields(log.Fields{
				"cmd": cmd,
			}).Error("Unknown command")
			return
		}
	}

	logger.Info("Control connection established, serving RPC")
	control.ServeConn(proto.Conn(), control.NewRPC(d))
}

// HandleCommandConnection is the initial point of contact on our main port.  The protocol
// implementation for inbound connections allows for identity exchange and signing prior to
// upgrading to TLS.  Once upgraded we will serve RPC to the agent.
func (d *Director) HandleCommandConnection(conn net.Conn) {
	var (
		err    error
		cmd    byte
		peerId string
	)
	defer conn.Close()

	// setup a base logger so all messages include our address
	logger := log.WithFields(log.Fields{
		"address": conn.RemoteAddr().String(),
		"type":    "command",
	})

	logger.Debug("New connection for Command RPC")

	proto := protocol.NewProtocol(conn)

	// Read our command
	cmd, err = proto.ReadByte()
	if err != nil {
		logger.WithError(err).Error("Failed to read command when setting up Control RPC")
		return
	}

	if cmd != protocol.TLS {
		logger.Error("Invalid command when setting up Control RPC")
		return
	}

	if peerId, err = proto.HandleStartTLS(d.identity, d.authority.Certificate); err != nil {
		logger.WithError(err).Error("Failed up handle Start TLS for Control RPC")
		return
	}

	// The connection is now upgraded to TLS and will be serving RPC to us
	// Load the agent's profile based on the peer ID from the TLS
	agent, ok := d.agents[peerId]
	if !ok {
		log.WithFields(log.Fields{
			"peerId": peerId,
		}).Error("No agent found for peerId")
		return
	}
	/*
		if err != nil {
			log.WithError(err).Error("Failed to load agent profile")
			return
		}*/

	// This will block
	agent.HandleConn(proto.Conn())
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

// LoadAgent takes a string ID and loads an Agent based on the data in our state.
// This is used by the control RPC implementation, as such it returns the control interface
// instead of the concrete implementation.
func (d *Director) LoadAgent(id string) (control.Agent, error) {
	// Try to load the identity
	identity, err := d.state.LoadIdentity(id)
	if err != nil {
		return nil, err
	}

	a := new(Agent)
	a.id = id
	a.identity = identity
	a.commands = make(chan *command.DispatchRequest)

	return a, nil
}

func (d *Director) RegisterAgent(id string, agent control.Agent) {
	d.agents[id] = agent.(*Agent)
}

func (a *Agent) HandleConn(conn net.Conn) {
	a.command = command.NewClient(conn)

	// Range over commands to send to the client
	for command := range a.commands {
		log.WithFields(log.Fields{
			"command": command,
		}).Debug("Received command for dispatching")

		reply := make(modules.Args)
		err := a.command.Dispatch(command, reply)
		if err != nil {
			log.WithFields(log.Fields{
				"error":   err,
				"command": command,
			}).Error("Failed to dispatch command")
		}
	}
}

func (a *Agent) Dispatch(module string, function string, args modules.Args) {
	a.commands <- &command.DispatchRequest{
		Module:   module,
		Function: function,
		Args:     args,
	}
}
