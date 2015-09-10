// Reeve server config
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
	DEBUG     bool
	DIRECTORS StringMap
	ID        string
)

func init() {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "reeve"
	}

	flag.BoolVar(&DEBUG, "debug", false, "Produce copius output")
	flag.Var(&DIRECTORS, "director", "Address(es) of director instances, can be specified multiple times")
	flag.StringVar(&ID, "id", hostname, "ID of this node")

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