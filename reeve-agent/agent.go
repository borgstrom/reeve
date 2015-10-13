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
	"github.com/borgstrom/reeve/rpc"
	"github.com/borgstrom/reeve/security"
	"github.com/borgstrom/reeve/version"
)

const (
	keyName = "reeve-agent.key"
	csrName = "reeve-agent.csr"
	crtName = "reeve-agent.crt"
	caName  = "reeve-ca.crt"
)

type Agent struct {
	identity             *security.Identity
	authorityCertificate *security.Certificate

	done         chan int
	bus          *eventbus.EventBus
	commandReady sync.WaitGroup
	controlReady sync.WaitGroup

	controlClient *rpc.ControlClient
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
			"You should purge the keys on this node and invalidate the identity on the directors.\n" +
			"This should not ever happen unless you've manually altered the keys.\n" +
			"If you can reproduce it, please file a bug at:\n" +
			"https://github.com/borgstrom/reeve/issues")
	}

	director := viper.GetString("director")
	port := viper.GetInt("port")

	log.Info("Starting event bus")
	a.bus = eventbus.NewEventBus()

	// Make our connections
	go a.makeConnections(director, port)

	// Signal handler
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL)
		sigReceived := <-sig
		log.WithFields(log.Fields{"signal": sigReceived}).Info("Received signal")
		a.done <- 1
	}()

	go a.register()

	// Wait until something tells us we're done
	<-a.done
	log.Info("Exiting")
}

func (a *Agent) register() {
	for {
		a.controlReady.Wait()

		reply, err := a.controlClient.Register(a.identity.Certificate.Subject.CommonName)
		if err != nil {
			log.WithError(err).Fatal("Failed to register")
		}
		log.WithFields(log.Fields{
			"expires": reply.Expires,
		}).Debug("Registered")

		time.Sleep(time.Duration(reply.Expires-1) * time.Second)
	}
}

func (a *Agent) makeConnections(director string, port int) {
	// Start a go routine for the Command RPC
	go func() {
		a.commandReady.Add(1)

		log.Info("Connecting to director for Command RPC")
		if err := protocol.Connect(director, port, a.handleCommandConnection); err != nil {
			log.WithFields(log.Fields{
				"error":    err,
				"director": director,
				"port":     port,
			}).Fatal("Failed to connect for command RPC")
		}
	}()

	// And one for the Control RPC
	go func() {
		a.controlReady.Add(1)

		// Wait for the command RPC channel and TLS to be ready
		a.commandReady.Wait()

		log.Info("Connecting to director for Control RPC")
		if err := protocol.Connect(director, port+1, a.handleControlConnection); err != nil {
			log.WithFields(log.Fields{
				"error":    err,
				"director": director,
				"port":     port + 1,
			}).Fatal("Failed to connect for control RPC")
		}
	}()
}

func (a *Agent) handleCommandConnection(proto *protocol.Protocol) error {
	var err error

	logger := log.WithFields(log.Fields{
		"address": proto.Conn().RemoteAddr().String(),
		"type":    "command",
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
			crtFile := config.Path("state", "agent.crt")
			if err = createPEM(crtFile, a.identity.Certificate); err != nil {
				logger.WithError(err).Fatal("Failed to save signed certificate!")
			}

			caFile := config.Path("state", "authority.crt")
			if err = createPEM(caFile, a.authorityCertificate); err != nil {
				logger.WithError(err).Fatal("Failed to save ca certificate!")
			}
		}
	}

	// Start TLS
	logger.Info("Upgrading connection to TLS")
	if err = proto.StartTLS(a.identity, a.authorityCertificate); err != nil {
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

	// Mark that we're good for TLS, this will trigger the control client to connect
	a.commandReady.Done()

	// Wait until the control RPC connection is ready
	a.controlReady.Wait()

	// Serve RPC
	logger.Info("Serving Command RPC")
	proto.ServeCommandRPC()

	return nil
}

func (a *Agent) handleControlConnection(proto *protocol.Protocol) error {
	var err error

	logger := log.WithFields(log.Fields{
		"address": proto.Conn().RemoteAddr().String(),
		"type":    "control",
	})

	// Start TLS
	if err = proto.StartTLS(a.identity, a.authorityCertificate); err != nil {
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

	logger.Debug("Control RPC connection established!")

	a.controlClient = rpc.NewControlClient(proto.Conn())

	a.controlReady.Done()

	// Some other mechanism for the client to call RPC on the director...
	// range over something...

	blah := make(chan int)
	<-blah

	a.done <- 1

	return nil
}

// prepareIdentity loads or creates our identity
func (a *Agent) prepareIdentity() {
	var (
		err       error
		fileBytes []byte
	)

	a.identity = security.NewIdentity(config.ID())

	log.WithFields(log.Fields{
		"state": config.Path("state"),
	}).Debug("Loading identity")

	caFile := config.Path("state", "authority.crt")
	_, err = os.Stat(caFile)
	if err == nil {
		// The ca exists, load it
		fileBytes, err = ioutil.ReadFile(caFile)
		a.authorityCertificate, err = security.CertificateFromPEM(fileBytes)
		if err != nil {
			log.WithError(err).Fatal("Failed to load ca certificate")
		}
	}

	keyFile := config.Path("state", "agent.key")
	_, err = os.Stat(keyFile)
	if err == nil {
		// The key exists, load it
		fileBytes, err = ioutil.ReadFile(keyFile)
		if err = a.identity.LoadKey(fileBytes); err != nil {
			log.WithError(err).Fatal("Failed to load private key")
		}
	} else {
		// Create a new one
		if err = a.identity.NewKey(); err != nil {
			log.WithError(err).Fatal("Failed to generate a new key")
		}

		// And save it
		if err = createPEM(keyFile, a.identity.Key); err != nil {
			log.WithError(err).WithFields(log.Fields{"key": keyFile}).Fatal("Failed to open key for writing")
		}
	}

	crtFile := config.Path("state", "agent.crt")
	_, err = os.Stat(crtFile)
	if err == nil {
		// The certificate exists, load it
		fileBytes, err = ioutil.ReadFile(crtFile)
		if err = a.identity.LoadCertificate(fileBytes); err != nil {
			log.WithError(err).Fatal("Failed to load certificate")
		}

		// At this point we are done and the identity is ready to use
		return
	}

	// See if we have an existing csr
	csrFile := config.Path("state", "agent.csr")
	_, err = os.Stat(csrFile)
	if err == nil {
		// The request exists, load it
		fileBytes, err = ioutil.ReadFile(csrFile)
		if err = a.identity.LoadRequest(fileBytes); err != nil {
			log.WithError(err).Fatal("Failed to load signing request")
		}
	} else {
		// Create a new request
		if err = a.identity.NewRequest(); err != nil {
			log.WithError(err).Fatal("Failed to create the new signing request")
		}

		// And save it
		if err = createPEM(csrFile, a.identity.Request); err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"file":  csrFile,
			}).Fatal("Failed to save request")
		}
	}
}

// createPEM takes a file name and a pem writer, creates a file and writes the pem bytes out
func createPEM(pemFile string, writer security.PEMWriter) error {
	f, err := os.Create(pemFile)
	if err != nil {
		return err
	}

	writer.WritePEM(f)
	f.Chmod(0400)

	return nil
}
