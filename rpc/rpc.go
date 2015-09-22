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
	"net/rpc"

	log "github.com/Sirupsen/logrus"
)

// As we take the rpc namespace we shim through some functions
var (
	NewClient = rpc.NewClient
	Register  = rpc.Register
	ServeConn = rpc.ServeConn
)

type Request struct {
}

type Reply struct {
	Ok   bool
	Data interface{}
}

type Test struct {
}

func (t *Test) Ping(request *Request, reply *Reply) error {
	log.Debug("Ping! Pong!")
	reply.Ok = true
	reply.Data = "Pong"
	return nil
}

func init() {
	var err error

	if err = rpc.Register(new(Test)); err != nil {
		log.WithError(err).Fatal("Failed to register Test RPC")
	}
}
