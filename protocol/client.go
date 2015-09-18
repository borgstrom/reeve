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
	Director string
	Conn     net.Conn
	Proto    *RawProtocol
}

// Creates a new Client and dials the director
func NewClient(director string) *Client {
	c := new(Client)

	c.Director = director

	return c
}

// Connect sets up the connection to the director
func (c *Client) Connect() error {
	conn, err := net.Dial("tcp", c.Director)
	if err != nil {
		return err
	}

	c.Conn = conn
	c.Proto = NewRawProtocol(c.Conn)

	return nil
}
