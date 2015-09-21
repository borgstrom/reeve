/*
 Reeve identity - manage identities

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
	"fmt"

	log "github.com/Sirupsen/logrus"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/borgstrom/reeve/state"
)

func init() {
	MainCommand.AddCommand(&cobra.Command{
		Use:   "pending",
		Short: "List pending identities",
		Run:   Pending,
	})

	MainCommand.AddCommand(&cobra.Command{
		Use:   "sign",
		Short: "Sign pending identities",
		Run:   Sign,
	})
}

func Pending(cmd *cobra.Command, args []string) {
	s := state.NewState(viper.GetStringSlice("etc.hosts"))

	fmt.Println("Pending identities:")

	identities, err := s.GetPendingIdentities()
	if err != nil {
		log.WithError(err).Fatal("Failed to get pending identities")
	}

	for _, identity := range identities {
		fmt.Println(identity)
	}
}

func Sign(cmd *cobra.Command, identities []string) {
	s := state.NewState(viper.GetStringSlice("etc.hosts"))

	authority, err := s.LoadAuthority()
	if err != nil {
		log.WithError(err).Fatal("Failed to load authority")
	}

	for _, id := range identities {
		identity, err := s.LoadIdentity(id)

		logger := log.WithFields(log.Fields{
			"identity": id,
		})

		if err != nil {
			logger.WithError(err).Fatal("Failed to load identity")
		}
		if identity == nil {
			logger.Error("Invalid identity")
			continue
		}

		if identity.Request == nil {
			logger.Error("The identity does not have a request attached to it")
			continue
		}

		if identity.Certificate != nil {
			logger.Error("The identity already has a certificate attached to it.")
			continue
		}

		cert, err := authority.Sign(identity.Request)
		if err != nil {
			logger.WithError(err).Fatal("Failed to sign the request")
		}

		identity.Certificate = cert
		if err = s.StoreIdentity(identity); err != nil {
			log.WithError(err).Fatal("Failed to store identity after signing request")
		}

		s.RemoveIdentityFromPending(identity)

		logger.Info("Succesfully signed identity")
	}
}
