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

// ServeControlConn takes a net connection, registers the Control module and serves RPC
func ServeControlConn(conn net.Conn) {
	rpc.Register(new(control.Control))
	rpc.ServeConn(conn)
}

// ServeCommandConn takes a net connection, registers the Command module and serves RPC
func ServeCommandConn(conn net.Conn) {
	rpc.Register(new(command.Command))
	rpc.ServeConn(conn)
}

// ControlClient is our custom rpc client for Control connections
type ControlClient struct {
	*rpc.Client
}

// NewControlClient return a new ControlClient based off of the provided connection
func NewControlClient(conn net.Conn) *ControlClient {
	return &ControlClient{rpc.NewClient(conn)}
}

// Register is a stub to the Control.Register RPC method
func (c *ControlClient) Register(agent string) (*control.RegisterReply, error) {
	reply := new(control.RegisterReply)

	err := c.Call("Control.Register", &agent, reply)
	if err != nil {
		return nil, err
	}

	return reply, nil
}

// CommandClient is our custom rpc client for Command connections
type CommandClient struct {
	*rpc.Client
}

// NewCommandClient takes a net connection and returns a new CommandClient
func NewCommandClient(conn net.Conn) *CommandClient {
	return &CommandClient{rpc.NewClient(conn)}
}

// Dispatch is a stub to the Command.Dispatch RPC method
func (c *CommandClient) Dispatch(request *command.DispatchRequest) (*command.DispatchReply, error) {
	reply := new(command.DispatchReply)

	err := c.Call("Command.Dispatch", request, reply)
	if err != nil {
		return nil, err
	}

	return reply, nil
}
