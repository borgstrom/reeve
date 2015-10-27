/*
Reeve director - saving & loading identity files

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

package state

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/borgstrom/reeve/security"
)

// LoadIdentityFiles takes the id of an identity and the full path names of the key, certificate &
// request files and will create a new identity and try to load the specified files.
func LoadIdentityFromFiles(id string, keyFile string, crtFile string, csrFile string) (*security.Identity, error) {
	var (
		err       error
		fileBytes []byte
	)

	i := new(security.Identity)
	i.Id = id

	_, err = os.Stat(keyFile)
	if err == nil {
		// The key exists, load it
		fileBytes, err = ioutil.ReadFile(keyFile)
		if err = i.LoadKey(fileBytes); err != nil {
			return nil, fmt.Errorf("Failed to load private key: %s", err)
		}
	} else {
		// Create a new one
		if err = i.NewKey(); err != nil {
			return nil, fmt.Errorf("Failed to generate a new key: %s", err)
		}

		// And save it
		if err = CreatePEM(keyFile, i.Key); err != nil {
			return nil, fmt.Errorf("Failed to save private key: %s", err)
		}
	}

	_, err = os.Stat(crtFile)
	if err == nil {
		// The certificate exists, load it
		fileBytes, err = ioutil.ReadFile(crtFile)
		if err = i.LoadCertificate(fileBytes); err != nil {
			return nil, fmt.Errorf("Failed to load certificate: %s", err)
		}

		// At this point we are done and the identity is ready to use
		return i, nil
	}

	// See if we have an existing csr
	_, err = os.Stat(csrFile)
	if err == nil {
		// The request exists, load it
		fileBytes, err = ioutil.ReadFile(csrFile)
		if err = i.LoadRequest(fileBytes); err != nil {
			return nil, fmt.Errorf("Failed to load signing request: %s", err)
		}
	} else {
		// Create a new request
		if err = i.NewRequest(); err != nil {
			return nil, fmt.Errorf("Failed to create the new signing request: %s", err)
		}

		// And save it
		if err = CreatePEM(csrFile, i.Request); err != nil {
			return nil, fmt.Errorf("Failed to save request: %s", err)
		}
	}

	return i, nil
}

// StoreIdentityInFiles takes an identity, along with a key, certificate and request file name
// and will write any of the Key, Certificate or Request on the identity if set.
func StoreIdentityInFiles(i *security.Identity, keyFile string, crtFile string, csrFile string) error {
	var err error

	if i.Key != nil {
		if err = CreatePEM(keyFile, i.Key); err != nil {
			return err
		}
	}

	if i.Certificate != nil {
		if err = CreatePEM(crtFile, i.Certificate); err != nil {
			return err
		}
	}

	if i.Request != nil {
		if err = CreatePEM(csrFile, i.Request); err != nil {
			return err
		}
	}

	return nil
}

// CreatePEM takes a file name and a pem writer, creates a file and writes the pem bytes out
func CreatePEM(pemFile string, writer security.PEMWriter) error {
	f, err := os.Create(pemFile)
	if err != nil {
		return err
	}

	writer.WritePEM(f)
	f.Chmod(0400)

	return nil
}
