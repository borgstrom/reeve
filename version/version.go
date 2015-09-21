// Reeve versioning
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

package version

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

const (
	Version = "0.1.1"
)

var (
	ProtocolVersion = ShortVersion(Version)

	// should be set during built with -X github.com/borgstrom/reeve/version.GitSHA=XXXXXXX
	GitSHA = "master"

	// for importing into the cli portions
	VersionCommand = &cobra.Command{
		Use:   "version",
		Short: "Show the current version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(Version)
		},
	}
)

// Only keep x.y from versions x.y.z-abc
func ShortVersion(v string) string {
	parts := strings.Split(v, ".")
	if len(parts) < 3 {
		return v
	}
	return strings.Join(parts[0:1], ".")
}
