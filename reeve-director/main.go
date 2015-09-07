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
	"fmt"
	"runtime"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/coreos/go-etcd/etcd"
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	log.WithFields(log.Fields{
		"id": id,
	}).Print("reeve-director starting")

	log.WithFields(log.Fields{
		"machines": etcd_machines,
	}).Print("Connecting to etcd")
	client := etcd.NewClient(etcd_machines)

	// register as a director
	go director_heartbeat(client)

	// find other directors

	// sleep forever
	for {
	}
}

func director_heartbeat(client *etcd.Client) {
	director_path := fmt.Sprintf("/directors/%s", id)

	for {
		log.WithFields(log.Fields{
			"path": director_path,
		}).Print("Heartbeat")

		if _, err := client.Set(director_path, "", 30); err != nil {
			log.Fatal(err)
		}
		time.Sleep(30 * time.Second)
	}
}
