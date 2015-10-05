/*
Reeve agent - config

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

package config

import (
	"os"
	"path/filepath"

	log "github.com/Sirupsen/logrus"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/borgstrom/reeve/version"
)

var (
	ConfigFile string
	Debug      bool
)

func PreRun(cmd *cobra.Command, args []string) {
	if Debug {
		log.SetLevel(log.DebugLevel)
	}

	InitConfig(ConfigFile)
}

func Init(cmd *cobra.Command) {
	cmd.AddCommand(version.VersionCommand)

	cmd.PersistentFlags().StringVarP(&ConfigFile, "config", "c", "", "Specify an explicit config file, defaults to the director config")
	cmd.PersistentFlags().BoolVarP(&Debug, "debug", "d", false, "Copious output")
}

func InitConfig(configFile string) {
	SetDefaults()

	if configFile != "" {
		if _, err := os.Stat(configFile); os.IsNotExist(err) {
			log.WithFields(log.Fields{"file": configFile}).Fatal("Config file does not exist")
		}

		// Load the config file if supplied
		viper.SetConfigFile(configFile)
	} else {
		// Otherwise use the defaults
		viper.SetConfigName("agent")
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
}

func SetDefaults() {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "reeve"
	}

	viper.SetDefault("id", hostname)

	viper.SetDefault("director", "reeve-director")
	viper.SetDefault("port", 4195)
	viper.SetDefault("state", "/var/lib/reeve") // TODO: this will need to change to support non-UNIX
}

// Frequently used setting
func ID() string {
	return viper.GetString("id")
}

// Path returns a joined path based on the config item in configName
func Path(configName string, parts ...string) string {
	parts = append([]string{viper.GetString(configName)}, parts...)
	return filepath.Join(parts...)
}
