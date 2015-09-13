/*
Reeve - test keys

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

package security

import (
	"bytes"
	"testing"
)

func TestEncoding(t *testing.T) {
	key, err := NewPrivateKey()
	if err != nil {
		t.Fatal("Failed to generate a key")
	}

	var pemBuf bytes.Buffer
	if err = key.WritePEM(&pemBuf); err != nil {
		t.Fatal("Failed to write the key to PEM format")
	}

	loaded_key, err := KeyFromPEM(pemBuf.Bytes())
	if err != nil {
		t.Fatal("Failed to read PEM version of key")
	}

	if !key.IsOnCurve(loaded_key.X, loaded_key.Y) {
		t.Fatal("Invalid loaded key")
	}
}
