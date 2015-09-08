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
	"syscall"

	log "github.com/Sirupsen/logrus"

	"github.com/coreos/go-etcd/etcd"

	"github.com/borgstrom/reeve/reeve-director/config"
	"github.com/borgstrom/reeve/reeve-director/director"
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

	d := &director.Director{
		Client: etcd.NewClient(config.ETCD_HOSTS),
	}

	// find other directors
	go d.DiscoverDirectors()

	// register as a director
	go d.DirectorHeartbeat()

	// block until we're interrupted
	cleanupChannel := make(chan os.Signal, 1)
	signal.Notify(cleanupChannel, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL, syscall.SIGHUP)
	<-cleanupChannel
	d.Client.Delete(config.EtcDirectorPath(), false)
	os.Exit(0)
}
