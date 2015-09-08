// Reeve director - entry point
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

package main

import (
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/coreos/go-etcd/etcd"

	"github.com/borgstrom/reeve/reeve-director/config"
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	if config.DEBUG == true {
		log.SetLevel(log.DebugLevel)
	}

	log.WithFields(log.Fields{
		"id": config.ID,
	}).Print("reeve-director starting")

	log.WithFields(log.Fields{
		"hosts": config.ETCD_HOSTS,
	}).Print("Connecting to etcd")
	client := etcd.NewClient(config.ETCD_HOSTS)

	// handle cleanup
	cleanupChannel := make(chan os.Signal, 1)
	signal.Notify(cleanupChannel, os.Interrupt)
	signal.Notify(cleanupChannel, syscall.SIGTERM)
	go func() {
		<-cleanupChannel
		cleanup(client)
		os.Exit(0)
	}()

	// find other directors
	go discoverDirectors(client)

	// register as a director
	go directorHeartbeat(client)

	// sleep forever
	for {
		time.Sleep(1 * time.Second)
	}
}

func cleanup(client *etcd.Client) {
	client.Delete(config.EtcDirectorPath(), false)
}

func directorHeartbeat(client *etcd.Client) {
	for {
		if _, err := client.Set(config.EtcDirectorPath(), "", 30); err != nil {
			log.Fatal(err)
		}
		time.Sleep(30 * time.Second)
	}
}

func discoverDirectors(client *etcd.Client) {
	log.Print("Discovering other directors")

	updates := make(chan *etcd.Response)

	go func() {
		if _, err := client.Watch(config.EtcDirectorsPath(), 0, true, updates, nil); err != nil {
			log.Fatal(err)
		}
	}()

	for res := range updates {
		log.WithFields(log.Fields{
			"action": res.Action,
			"key":    res.Node.Key,
			"value":  res.Node.Value,
		}).Debug("New event")

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
