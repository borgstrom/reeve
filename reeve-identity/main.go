/*
 Reeve identity - entry point

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
	log "github.com/Sirupsen/logrus"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/borgstrom/reeve/version"
)

var MainCommand = &cobra.Command{
	Use:              "reeve-identity",
	Short:            "Manage security identities (keys & certificates)",
	PersistentPreRun: InitConfig,
}

var (
	ConfigFile string
	Debug      bool
)

func init() {
	MainCommand.AddCommand(version.VersionCommand)

	MainCommand.PersistentFlags().StringVarP(&ConfigFile, "config", "c", "", "Specify an explicit config file, defaults to the director config")
	MainCommand.PersistentFlags().BoolVarP(&Debug, "debug", "d", false, "Copious output")
}

func main() {
	MainCommand.Execute()
}

func InitConfig(cmd *cobra.Command, args []string) {
	if Debug {
		log.SetLevel(log.DebugLevel)
	}

	// Load the config
	if ConfigFile != "" {
		viper.SetConfigFile(ConfigFile)
	} else {
		viper.SetConfigName("director")
		viper.AddConfigPath("/etc/reeve")
		viper.AddConfigPath("$HOME/.reeve")
	}

	err := viper.ReadInConfig()
	if err != nil {
		// Check if we got an unsupported config error
		// If so it means that no files were found, and we can just skip it using our defaults
		_, ok := err.(viper.UnsupportedConfigError)
		if !ok {
			log.WithError(err).Fatal("Could not read config")
		}

		log.Debug("No config file available, using all defaults")
	}

	// Defaults
	// TODO move this into the director, since we want to share its config
	// TODO director_config.SetDefaults()
	viper.SetDefault("etc", map[string]interface{}{
		"hosts": []string{"http://127.0.0.1:2379"},
	})
}
