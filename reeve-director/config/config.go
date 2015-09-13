// Reeve director config
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

package config

import (
	"flag"
	"fmt"
	"os"

	log "github.com/Sirupsen/logrus"

	"github.com/borgstrom/reeve/version"
)

// StringMap
type StringMap []string

func (i *StringMap) String() string {
	return fmt.Sprint(*i)
}

func (i *StringMap) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var (
	DEBUG      bool
	ETCD_HOSTS StringMap = []string{"http://127.0.0.1:2379"}
	ID         string
	PORT       int
	HOST       string
)

func init() {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "reeve"
	}

	flag.BoolVar(&DEBUG, "debug", false, "Produce copius output")
	flag.Var(&ETCD_HOSTS, "etcd", "Address(es) of etcd instances, can be specified multiple times")
	flag.StringVar(&ID, "id", hostname, "ID of this node")
	flag.StringVar(&HOST, "host", "", "The address to bind to")
	flag.IntVar(&PORT, "port", 4195, "The port to listen on")

	var showVersion = flag.Bool("version", false, "Show the current version")

	flag.Parse()

	if DEBUG == true {
		log.SetLevel(log.DebugLevel)
	}

	if *showVersion == true {
		fmt.Printf(version.Version)
		os.Exit(0)
	}
}
