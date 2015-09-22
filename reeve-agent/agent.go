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
	"syscall"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/spf13/viper"

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
	client               *protocol.Client
	authorityCertificate *security.Certificate
}

func NewAgent() *Agent {
	a := new(Agent)

	return a
}

func (a *Agent) Run() {
	var (
		err error
	)

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

	logger := log.WithFields(log.Fields{
		"director": viper.GetString("director"),
	})

	// Connect to the director
	logger.Info("Connecting to director")
	a.client = protocol.NewClient(viper.GetString("director"))
	if err = a.client.Connect(); err != nil {
		log.WithError(err).Fatal("Failed to connect to the director")
	}

	//
	logger.Debug("Verifying protocol")
	if err = a.client.Proto.Validate(); err != nil {
		log.WithError(err).Fatal("Failed to validate the protocol")
	}
	logger.Debug("Protocol verified")

	// We need to get the director to sign our identity before we can do anything else
	for !a.identity.IsSigned() {
		logger.Debug("Sending signing request")
		if err = a.client.Proto.SendSigningRequest(a.identity.Request); err != nil {
			logger.WithError(err).Fatal("Failed to send signing request to the director")
		}

		logger.Debug("Reading response")
		resp, err := a.client.Proto.ReadStringWithDeadline()
		if err != nil {
			logger.WithError(err).Fatal("Failed to read response to csr")
		}
		logger.WithFields(log.Fields{"resp": resp}).Debug("Handling response")

		if resp == protocol.Ack {
			logger.Info("Waiting for our identity to be signed by the director...")
			time.Sleep(15 * time.Second)
		} else if resp == protocol.Response {
			logger.Info("Receiving signed certificate")
			a.identity.Certificate, err = a.client.Proto.HandleCertificate()
			if err != nil {
				logger.WithError(err).Fatal("Failed to read signed certificate!")
			}

			logger.Info("Receving authority certificate")
			a.authorityCertificate, err = a.client.Proto.HandleCertificate()
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
	if err = a.client.Proto.StartTLS(a.identity, a.authorityCertificate); err != nil {
		logger.WithError(err).Fatal("Failed to start TLS")
	}

	// Read a string, this will happen over the now encrypted channel
	resp, err := a.client.Proto.ReadString()
	if err != nil {
		logger.WithError(err).Fatal("Failed to ack TLS")
	}

	if resp != protocol.Ack {
		logger.WithFields(log.Fields{"resp": resp}).Fatal("Failed to receive Ack in response to start TLS")
	}

	logger.Info("TLS connection established")

	rpcClient := rpc.NewClient(a.client.Conn)
	reply := new(rpc.Reply)
	request := new(rpc.Request)
	err = rpcClient.Call("Test.Ping", &request, &reply)
	if err != nil {
		logger.WithError(err).Fatal("Ping failed")
	}

	logger.Info(reply.Data)

	// block until interrupted
	cleanupChannel := make(chan os.Signal, 1)
	signal.Notify(cleanupChannel, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL)
	<-cleanupChannel
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
