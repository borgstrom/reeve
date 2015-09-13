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
	"net"
)

type Client struct {
	director string
	conn     net.Conn
	proto    *RawProtocol
}

// Creates a new Client and dials the director
func NewClient(director string) *Client {
	c := new(Client)

	c.director = director

	return c
}

// Connect sets up the connection to the director
func (c *Client) Connect() error {
	conn, err := net.Dial("tcp", c.director)
	if err != nil {
		return err
	}

	c.conn = conn
	c.proto = NewRawProtocol(c.conn)

	// We need to send our protocolIdentifer + our supported version
	if err = c.proto.Announce(); err != nil {
		return err
	}

	// If our certificate is not signed by the CA yet then we need to get a signed copy of the cert
	// before we upgrade the connection to TLS

	// Send the PEM version of our unsigned certificate
	//

	return nil
}
