/*
 Reeve - Command RPC

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

package command

import (
	_ "github.com/borgstrom/reeve/modules/file"
	_ "github.com/borgstrom/reeve/modules/test"
)

type CommandRequest struct {
	module   string
	function string
	args     []interface{}
}

type CommandReply struct {
	Ok bool
}

type Command struct {
}

func (c *Command) Call(request *CommandRequest, reply *CommandReply) error {
	return nil
}
