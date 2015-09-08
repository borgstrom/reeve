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
	"strings"
	"time"

	"github.com/coreos/go-etcd/etcd"

	log "github.com/Sirupsen/logrus"

	"github.com/borgstrom/reeve/reeve-director/config"
)

const (
	heartbeatInterval = 10
)

type Director struct {
	Client *etcd.Client
}

func (d Director) DirectorHeartbeat() {
	for {
		if _, err := d.Client.Set(config.EtcDirectorPath(), "", heartbeatInterval); err != nil {
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
		if _, err := d.Client.Watch(config.EtcDirectorsPath(), 0, true, updates, nil); err != nil {
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
