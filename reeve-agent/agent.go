/*
Reeve agent - main code

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
	"io/ioutil"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/spf13/viper"

	"github.com/borgstrom/reeve/eventbus"
	"github.com/borgstrom/reeve/protocol"
	"github.com/borgstrom/reeve/reeve-agent/config"
	"github.com/borgstrom/reeve/rpc/command"
	"github.com/borgstrom/reeve/rpc/control"
	"github.com/borgstrom/reeve/security"
	"github.com/borgstrom/reeve/state"
	"github.com/borgstrom/reeve/version"
)

const (
	keyName = "reeve-agent.key"
	csrName = "reeve-agent.csr"
	crtName = "reeve-agent.crt"
	caName  = "reeve-agent-ca.crt"
)

type Agent struct {
	identity             *security.Identity
	authorityCertificate *security.Certificate

	done chan int
	bus  *eventbus.EventBus

	connectionsReady sync.WaitGroup
	commandReady     sync.WaitGroup
	controlReady     sync.WaitGroup

	controlClient *control.ControlClient
}

func NewAgent() *Agent {
	a := new(Agent)

	a.done = make(chan int)

	return a
}

func (a *Agent) Run() {
	log.WithFields(log.Fields{
		"id":      config.ID(),
		"version": version.Version,
		"git":     version.GitSHA,
	}).Print("reeve-agent starting")

	// Get our Identity ready
	a.prepareIdentity()

	if !a.identity.IsValid() {
		log.Fatal("Our identity is not valid!\n" +
			"You should purge the keys on this agent and invalidate the identity on the directors.\n" +
			"This should not ever happen unless you've manually altered the keys.\n" +
			"If you can reproduce it, please file a bug at:\n" +
			"https://github.com/borgstrom/reeve/issues")
	}

	director := viper.GetString("director")
	port := viper.GetInt("port")

	log.Info("Starting event bus")
	a.bus = eventbus.NewEventBus()

	// Make our connections
	a.connectionsReady.Add(1)
	go a.makeConnections(director, port)

	// Signal handler
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL)
		sigReceived := <-sig
		log.WithFields(log.Fields{"signal": sigReceived}).Info("Received signal")
		a.done <- 1
	}()

	a.connectionsReady.Wait()

	go a.register()

	// Wait until something tells us we're done
	<-a.done
	log.Info("Exiting")
}

func (a *Agent) register() {
	for {
		// Before registering we need both the command & control RPC interfaces to be ready
		a.commandReady.Wait()
		a.controlReady.Wait()

		log.Debug("Registering")
		reply, err := a.controlClient.Register(a.identity.Certificate.Subject.CommonName)
		if err != nil {
			log.WithError(err).Fatal("Failed to register")
		}

		if !reply.Ok {
			log.Error("Failed to register, retrying in 5 seconds...")
			time.Sleep(5 * time.Second)
			continue
		}

		log.WithFields(log.Fields{
			"expires": reply.Expires,
		}).Debug("Registered")

		time.Sleep(time.Duration(reply.Expires-1) * time.Second)
	}
}

func (a *Agent) makeConnections(director string, port int) {
	// Start a go routine for the Control RPC
	go func() {
		a.controlReady.Add(1)

		log.Info("Connecting to director for Control RPC")
		if err := protocol.Connect(director, port, a.handleControlConnection); err != nil {
			log.WithFields(log.Fields{
				"error":    err,
				"director": director,
				"port":     port,
			}).Fatal("Failed to connect for Control RPC")
		}
	}()

	// And one for the Command RPC
	go func() {
		a.commandReady.Add(1)

		// Wait for the Control RPC channel and TLS to be ready
		a.controlReady.Wait()

		log.Info("Connecting to director for Command RPC")
		if err := protocol.Connect(director, port+1, a.handleCommandConnection); err != nil {
			log.WithFields(log.Fields{
				"error":    err,
				"director": director,
				"port":     port + 1,
			}).Fatal("Failed to connect for control RPC")
		}
	}()

	go a.connectionsReady.Done()
}

func (a *Agent) handleControlConnection(proto *protocol.Protocol) error {
	var err error

	logger := log.WithFields(log.Fields{
		"address": proto.Conn().RemoteAddr().String(),
		"type":    "control",
	})

	logger.Debug("Verifying protocol")
	if err = proto.Validate(); err != nil {
		log.WithError(err).Fatal("Failed to validate the protocol")
	}
	logger.Debug("Protocol verified")

	// We need to get the director to sign our identity before we can do anything else
	for !a.identity.IsSigned() {
		logger.Debug("Sending signing request")
		if err = proto.SendSigningRequest(a.identity.Request); err != nil {
			logger.WithError(err).Fatal("Failed to send signing request to the director")
		}

		logger.Debug("Reading response")
		cmd, err := proto.ReadByte()
		if err != nil {
			logger.WithError(err).Fatal("Failed to read response to csr")
		}

		if cmd == protocol.Ack {
			logger.Info("Waiting for our identity to be signed by the director...")
			time.Sleep(15 * time.Second)
		} else if cmd == protocol.Response {
			logger.Info("Receiving signed certificate")
			a.identity.Certificate, err = proto.HandleCertificate()
			if err != nil {
				logger.WithError(err).Fatal("Failed to read signed certificate!")
			}

			logger.Info("Receving authority certificate")
			a.authorityCertificate, err = proto.HandleCertificate()
			if err != nil {
				logger.WithError(err).Fatal("Failed to read authority certificate")
			}

			// Store the new certificates in local files
			crtFile := config.Path("state", crtName)
			if err = state.CreatePEM(crtFile, a.identity.Certificate); err != nil {
				logger.WithError(err).Fatal("Failed to save signed certificate!")
			}

			caFile := config.Path("state", caName)
			if err = state.CreatePEM(caFile, a.authorityCertificate); err != nil {
				logger.WithError(err).Fatal("Failed to save ca certificate!")
			}
		}
	}

	// Start TLS
	logger.Info("Upgrading connection to TLS")
	if _, err := proto.StartTLS(a.identity, a.authorityCertificate); err != nil {
		logger.WithError(err).Fatal("Failed to start TLS")
	}

	// Read a string, this will happen over the now encrypted channel
	cmd, err := proto.ReadByte()
	if err != nil {
		logger.WithError(err).Fatal("Failed to ack TLS")
	}

	if cmd != protocol.Ack {
		logger.Fatal("Failed to receive Ack in response to start TLS")
	}

	logger.Info("TLS connection established")

	// Mark that we're good for TLS, this will trigger the command client to connect
	a.controlReady.Done()

	logger.Debug("Control RPC connection established!")

	a.controlClient = control.NewClient(proto.Conn())

	// Some other mechanism for the client to call RPC on the director...
	// range over something...

	blah := make(chan int)
	<-blah

	return nil
}

func (a *Agent) handleCommandConnection(proto *protocol.Protocol) error {
	var err error

	logger := log.WithFields(log.Fields{
		"address": proto.Conn().RemoteAddr().String(),
		"type":    "command",
	})

	// Start TLS
	if _, err := proto.StartTLS(a.identity, a.authorityCertificate); err != nil {
		logger.WithError(err).Fatal("Failed to start TLS")
	}

	// We are now encrypted, read an Ack over the encrypted channel
	cmd, err := proto.ReadByte()
	if err != nil {
		logger.WithError(err).Fatal("Failed to read response to csr")
	}

	if cmd != protocol.Ack {
		logger.Fatal("Failed to receive Ack following TLS upgrade")
	}

	go a.commandReady.Done()

	// Serve RPC
	logger.Info("Serving Command RPC")
	command.ServeConn(proto.Conn(), command.NewRPC())

	return nil
}

// prepareIdentity loads or creates our identity
func (a *Agent) prepareIdentity() {
	var (
		err       error
		fileBytes []byte
	)

	caFile := config.Path("state", caName)
	_, err = os.Stat(caFile)
	if err == nil {
		// The ca cert exists, load it
		fileBytes, err = ioutil.ReadFile(caFile)
		a.authorityCertificate, err = security.CertificateFromPEM(fileBytes)
		if err != nil {
			log.WithError(err).Fatal("Failed to load ca certificate")
		}
	}

	log.WithFields(log.Fields{
		"state": config.Path("state"),
	}).Debug("Loading identity")

	a.identity, err = state.LoadIdentityFromFiles(
		config.ID(),
		config.Path("state", keyName),
		config.Path("state", crtName),
		config.Path("state", csrName),
	)
	if err != nil {
		log.WithError(err).Fatal("Failed to load identity")
	}

}
