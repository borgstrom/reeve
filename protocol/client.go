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

	"github.com/borgstrom/reeve/rpc"
)

type Client struct {
	director string
	port     int
	address  string

	conn net.Conn
}

// Creates a new Client and dials the director.  Director should be in the form <host>:<port>
func NewClient(director string, port int) *Client {
	c := new(Client)

	c.director = director
	c.port = port
	c.address = fmt.Sprintf("%s:%d", director, port)

	return c
}

// Connect sets up the connection to the director
func (c *Client) Connect() error {
	var err error

	c.conn, err = net.Dial("tcp", c.address)
	if err != nil {
		return err
	}

	return nil
}

// NewProtocol returns a new Protocol object based on this client's connection
func (c *Client) NewProtocol() *Protocol {
	p := NewProtocol(c.conn)

	// Set the server name that we'll use during TLS verification
	p.SetServerName(c.director)

	return p
}

// ServeRPC passes the connection of the client to the RPC framework
func (c *Client) ServeRPC() {
	rpc.ServeConn(c.conn)
}
