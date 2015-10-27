/*
 Reeve - Modules

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

package control

import (
	"net"
	"net/rpc"

	log "github.com/Sirupsen/logrus"
)

// ServeConn takes a net connection, registers the Control module and serves RPC
func ServeConn(conn net.Conn, c *ControlRPC) {
	rpc.RegisterName("Control", c)
	rpc.ServeConn(conn)
}

// ControlClient is our custom rpc client for Control connections
type ControlClient struct {
	*rpc.Client
}

type Agent interface {
}

type Director interface {
	LoadAgent(string) (Agent, error)
	RegisterAgent(string, Agent)
}

type ControlRPC struct {
	dir Director
}

func NewRPC(dir Director) *ControlRPC {
	c := new(ControlRPC)
	c.dir = dir
	return c
}

// NewControlClient return a new ControlClient based off of the provided connection
func NewClient(conn net.Conn) *ControlClient {
	return &ControlClient{rpc.NewClient(conn)}
}

type RegisterReply struct {
	Ok      bool
	Expires int
}

// Register is a stub to the Control.Register RPC method
func (c *ControlClient) Register(agent string) (*RegisterReply, error) {
	reply := new(RegisterReply)

	err := c.Call("Control.Register", &agent, reply)
	if err != nil {
		return nil, err
	}

	return reply, nil
}

func (c *ControlRPC) Register(agent *string, reply *RegisterReply) error {
	a, err := c.dir.LoadAgent(*agent)
	if err != nil {
		log.WithFields(log.Fields{
			"agent": *agent,
			"error": err,
		}).Error("Failed to load agent")

		reply.Ok = false
		reply.Expires = -1
	} else {
		log.WithFields(log.Fields{
			"agent": *agent,
		}).Debug("Registering agent")

		c.dir.RegisterAgent(*agent, a)
		reply.Ok = true
		reply.Expires = 30
	}

	return nil
}
