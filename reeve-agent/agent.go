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
	"os"
	"os/signal"
	"syscall"

	log "github.com/Sirupsen/logrus"

	"github.com/borgstrom/reeve/protocol"
	"github.com/borgstrom/reeve/reeve-agent/config"
	"github.com/borgstrom/reeve/security"
)

type Agent struct {
	identity *security.Identity
	client   *protocol.Client
}

func NewAgent() *Agent {
	a := new(Agent)
	return a
}

func (a Agent) Run() {
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

func (a Agent) loadIdentity() {
}
