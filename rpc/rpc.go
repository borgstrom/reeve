/*
 Reeve - RPC

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

package rpc

import (
	"net"
	"net/rpc"

	"github.com/borgstrom/reeve/rpc/command"
	"github.com/borgstrom/reeve/rpc/control"
)

func ServeControlConn(conn net.Conn) {
	rpc.Register(new(control.Control))
	rpc.ServeConn(conn)
}

func ServeCommandConn(conn net.Conn) {
	rpc.Register(new(command.Command))
	rpc.ServeConn(conn)
}

type ControlClient struct {
	*rpc.Client
}

// NewControlClient return a new ControlClient based off of the provided connection
func NewControlClient(conn net.Conn) *ControlClient {
	return &ControlClient{rpc.NewClient(conn)}
}

func (c *ControlClient) Register(agent string) (*control.RegisterReply, error) {
	reply := new(control.RegisterReply)

	err := c.Call("Control.Register", &agent, reply)
	if err != nil {
		return nil, err
	}

	return reply, nil
}
