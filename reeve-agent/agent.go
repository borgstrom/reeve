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
	"path"
	"syscall"

	log "github.com/Sirupsen/logrus"

	"github.com/borgstrom/reeve/protocol"
	"github.com/borgstrom/reeve/reeve-agent/config"
	"github.com/borgstrom/reeve/security"
)

const (
	keyName = "reeve-agent.key"
	csrName = "reeve-agent.csr"
	crtName = "reeve-agent.crt"
)

type Agent struct {
	identity *security.Identity
	client   *protocol.Client
}

func NewAgent() *Agent {
	a := new(Agent)
	return a
}

func (a *Agent) Run() {
	// Get our Identity ready
	a.loadIdentity()

	// Connect to the director
	log.WithFields(log.Fields{
		"director": config.DIRECTOR,
	}).Info("Connecting to director")

	a.client = protocol.NewClient(config.DIRECTOR)
	if err := a.client.Connect(); err != nil {
		log.WithFields(log.Fields{
			"error":    err,
			"director": config.DIRECTOR,
		}).Fatal("Failed to connect to the director")
	}
	log.WithFields(log.Fields{
		"director": config.DIRECTOR,
	}).Info("Connected to director")

	// block until interrupted
	cleanupChannel := make(chan os.Signal, 1)
	signal.Notify(cleanupChannel, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL)
	<-cleanupChannel
}

// loadIdentity loads or creates our identity
func (a *Agent) loadIdentity() {
	var (
		err       error
		fileBytes []byte
	)

	a.identity = security.NewIdentity(config.ID)

	keyFile := path.Join(config.KEYDIR, keyName)
	_, err = os.Stat(keyFile)
	if err == nil {
		// The key exists, load it
		fileBytes, err = ioutil.ReadFile(keyFile)
		if err = a.identity.LoadKey(fileBytes); err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Fatal("Failed to load private key")
		}
	} else {
		// Create a new one
		if err = a.identity.NewKey(); err != nil {
			log.WithError(err).Fatal("Failed to generate a new key")
		}

		// And save it
		f, err := os.Create(keyFile)
		if err != nil {
			log.WithError(err).WithFields(log.Fields{"key": keyFile}).Fatal("Failed to open key for writing")
		}

		// Set an appropriate mode
		f.Chmod(0400)

		// Write it
		a.identity.Key.WritePEM(f)
	}

	crtFile := path.Join(config.KEYDIR, crtName)
	_, err = os.Stat(crtFile)
	if err == nil {
		// The certificate exists, load it
		fileBytes, err = ioutil.ReadFile(crtFile)
		if err = a.identity.LoadCertificate(fileBytes); err != nil {
			log.WithError(err).Fatal("Failed to load certificate")
		}

		// At this point we are done, get out of here
		return
	}

	// See if we have an existing csr
	csrFile := path.Join(config.KEYDIR, csrName)
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
		f, err := os.Create(csrFile)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"key":   csrFile,
			}).Fatal("Failed to open csr for writing")
		}

		// Set an appropriate mode
		f.Chmod(0400)

		// Write it
		a.identity.Request.WritePEM(f)
	}
}
