/*
Reeve - client implementation

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

package protocol

import (
	"fmt"
	"net"
	"strings"
)

type Client struct {
	Director string
	Conn     net.Conn
	Proto    *RawProtocol
}

// Creates a new Client and dials the director.  Director should be in the form <host>:<port>
func NewClient(director string) *Client {
	c := new(Client)

	c.Director = director

	return c
}

// Connect sets up the connection to the director
func (c *Client) Connect() error {
	var err error

	// Split our director address at the port as we need just the name
	hostParts := strings.Split(c.Director, ":")
	if len(hostParts) != 2 {
		return fmt.Errorf("Invalid director address: %s", c.Director)
	}

	c.Conn, err = net.Dial("tcp", c.Director)
	if err != nil {
		return err
	}

	// Wrap the connection in our protocol
	c.Proto = NewRawProtocol(c.Conn)

	// Set the server name that we'll use during TLS verification
	c.Proto.SetServerName(hostParts[0])

	return nil
}
