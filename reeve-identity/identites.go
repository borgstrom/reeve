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
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/borgstrom/reeve/state"
)

var Script bool = false

func init() {
	MainCommand.AddCommand(&cobra.Command{
		Use:   "pending",
		Short: "List pending identities",
		Run:   Pending,
	})

	MainCommand.AddCommand(&cobra.Command{
		Use:   "remove",
		Short: "Remove an identity",
		Run:   Remove,
	})

	MainCommand.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Show information about an identity",
		Run:   Show,
	})

	MainCommand.AddCommand(&cobra.Command{
		Use:   "sign",
		Short: "Sign pending identities",
		Run:   Sign,
	})

	MainCommand.PersistentFlags().BoolVarP(&Script, "script", "s", false, "If set no confirmations will be required")
}

func Pending(cmd *cobra.Command, args []string) {
	s := state.NewState(viper.GetStringSlice("etc.hosts"))

	fmt.Println("Pending identities:")

	identities, err := s.GetPendingIdentities()
	if err != nil {
		fmt.Printf("Failed to get pending identities: %s", err)
	}

	for _, identity := range identities {
		fmt.Println(identity)
	}
}

func Sign(cmd *cobra.Command, identities []string) {
	if len(identities) == 0 {
		fmt.Printf("Please provide at least one identity to sign")
		return
	}

	s := state.NewState(viper.GetStringSlice("etc.hosts"))

	authority, err := s.LoadAuthority()
	if err != nil {
		fmt.Printf("Failed to load authority: %s", err)
	}

	for _, id := range identities {
		identity, err := s.LoadIdentity(id)
		if err != nil {
			fmt.Printf("Failed to load identity %s: %s", id, err)
		}
		if identity == nil {
			fmt.Printf("Invalid identity: %s", id)
			continue
		}

		if identity.Request == nil {
			fmt.Printf("The identity, %s, does not have a request attached to it", id)
			continue
		}

		if identity.Certificate != nil {
			fmt.Printf("The identity, %s, already has a certificate attached to it.", id)
			continue
		}

		cert, err := authority.Sign(identity.Request)
		if err != nil {
			fmt.Printf("Failed to sign the request for %s: %s", id, err)
		}

		if err = s.StoreAuthoritySerial(authority); err != nil {
			fmt.Printf("Failed to store the authority serial number for %s: %s", id, err)
		}

		identity.Certificate = cert
		if err = s.StoreIdentity(identity); err != nil {
			fmt.Printf("Failed to store identity after signing request for %s: %s", id, err)
		}

		s.RemoveIdentityFromPending(identity)

		fmt.Printf("Signed %s", id)
	}
}

func Remove(cmd *cobra.Command, identities []string) {
	var (
		answer string
	)

	if len(identities) == 0 {
		fmt.Printf("Please provide at least one identity to remove")
		return
	}

	s := state.NewState(viper.GetStringSlice("etc.hosts"))

	for _, id := range identities {
		identity, err := s.LoadIdentity(id)
		if err != nil {
			fmt.Printf("Failed to load identity %s: %s", id, err)
		}
		if identity == nil {
			fmt.Printf("Invalid identity: %s", id)
			continue
		}

		answer = ""
		for !Script && answer != "y" {
			fmt.Printf("Removing %s.  Continue? [y/N]: ", id)
			if _, err = fmt.Scanln(&answer); err != nil {
				fmt.Printf("Failed to read input: %s", err)
			}
			answer = strings.ToLower(answer)
			if answer == "n" {
				return
			}
		}

		if err = s.RemoveIdentity(identity); err != nil {
			fmt.Printf("Failed to remove identity: %s", err)
		}

		fmt.Printf("Removed %s\n", id)
	}
}

func Show(cmd *cobra.Command, identities []string) {
	if len(identities) == 0 {
		fmt.Printf("Please provide at least one identity to show")
		return
	}

	s := state.NewState(viper.GetStringSlice("etc.hosts"))

	fmt.Printf("Found %d identities\n", len(identities))

	for _, id := range identities {
		identity, err := s.LoadIdentity(id)
		if err != nil {
			fmt.Printf("Failed to load identity %s: %s", id, err)
		}
		if identity == nil {
			fmt.Printf("Invalid identity %s", id)
			continue
		}

		fmt.Print("\n")
		fmt.Printf("Id: %s\n", identity.Id)
		fmt.Printf("Is Valid: %t\n", identity.IsValid())
		fmt.Printf("Is Signed: %t\n", identity.IsSigned())
		fmt.Printf("Has key: %t\n", identity.Key != nil)
		fmt.Printf("Fingerprint: % x\n", identity.Fingerprint())
		fmt.Printf("Serial Number: %d\n", identity.Certificate.SerialNumber)
		fmt.Printf("Created: %s\n", identity.Certificate.NotBefore)
		fmt.Printf("Expires: %s\n", identity.Certificate.NotAfter)
	}
}
