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
	"fmt"
	"reflect"

	log "github.com/Sirupsen/logrus"

	"github.com/borgstrom/reeve/modules"

	_ "github.com/borgstrom/reeve/modules/file"
	_ "github.com/borgstrom/reeve/modules/test"
)

type Args []interface{}

type DispatchRequest struct {
	Module   string
	Function string
	Args     Args
}

type DispatchReply struct {
	Error  string
	Ok     bool
	Result interface{}
}

type Command byte

func (c *Command) Dispatch(request *DispatchRequest, reply *DispatchReply) error {
	log.WithFields(log.Fields{
		"module":   request.Module,
		"function": request.Function,
		"args":     request.Args,
	}).Debug("Dispatching")

	fun := modules.FindFunction(request.Module, request.Function)
	if fun == nil {
		reply.Error = fmt.Sprintf("Invalid module/function: %s.%s", request.Module, request.Function)
		reply.Ok = false
		return nil
	}

	// Now that we have a valid function we setup a recover block so that invalid calls (i.e. incorrect
	// arguments) don't cause a panic
	defer func() {
		if r := recover(); r != nil {
			log.WithFields(log.Fields{
				"error":    r,
				"module":   request.Module,
				"function": request.Function,
				"args":     request.Args,
			}).Error("Failed to dispatch")

			reply.Error = fmt.Sprintf("Failed to dispatch: %s", r)
			reply.Ok = false
		}
	}()

	// Reflect on our function
	funcValue := reflect.ValueOf(fun)

	// For each of the args provided reflect on it and add it to a new slice
	funcArgs := make([]reflect.Value, len(request.Args))
	for i, v := range request.Args {
		funcArgs[i] = reflect.ValueOf(v)
	}

	// Call the function
	results := funcValue.Call(funcArgs)
	if !results[1].IsNil() {
		// We got an error
		err := results[1].Interface().(error)
		reply.Error = fmt.Sprintf("Failed to call dispatched function: %s", err.Error())
		reply.Ok = false
		return nil
	}

	// Store the result in the reply
	reply.Result = results[0].Interface()

	// We're good
	reply.Ok = true
	return nil
}
