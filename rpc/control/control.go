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
	log "github.com/Sirupsen/logrus"
)

type RegisterReply struct {
	Ok      bool
	Expires int
}

type Control byte

func (c *Control) Register(agent *string, reply *RegisterReply) error {
	log.WithFields(log.Fields{
		"agent": *agent,
	}).Debug("New Registration")
	reply.Ok = true
	reply.Expires = 30
	return nil
}
