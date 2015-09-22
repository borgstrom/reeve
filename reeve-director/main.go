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
	"runtime"

	"github.com/spf13/cobra"

	"github.com/borgstrom/reeve/reeve-director/config"
)

var MainCommand = &cobra.Command{
	Use:              "reeve-director",
	Short:            "Direct and control agents",
	PersistentPreRun: config.PreRun,
}

var RunCommand = &cobra.Command{
	Use:   "run",
	Short: "Run the director",

	Run: func(cmd *cobra.Command, args []string) {
		NewDirector().Run()
	},
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	config.Init(MainCommand)

	MainCommand.AddCommand(RunCommand)
}

func main() {
	MainCommand.Execute()
}
