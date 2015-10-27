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

package modules

import (
	"errors"

	"github.com/spf13/cast"
)

type Args map[string]interface{}

var ErrNoArg = errors.New("No argument exists at that name")

// GetString takes the name of an argument and returns a string and an error.
func (args Args) GetString(name string) (string, error) {
	v, ok := args[name]
	if !ok {
		return "<invalid argument>", ErrNoArg
	}

	str, err := cast.ToStringE(v)
	if err != nil {
		return "<failed to cast>", err
	}
	return str, nil
}

// GetInt takes the name of an argument and returns an integer and an error
func (args Args) GetInt(name string) (int, error) {
	v, ok := args[name]
	if !ok {
		return -1 << 7, ErrNoArg
	}

	i, err := cast.ToIntE(v)
	if err != nil {
		return -1 << 7, err
	}
	return i, nil
}

// Function is the signature of a module function, it takes two argument maps -- one for input and
// one for output.  The function will return an appropriate error on failure.
type Function func(Args, Args) error

// Functions is a map of string names to module functions
type Functions map[string]Function

// The Module struct binds a map of Functions to a module name
type Module struct {
	Name      string
	Functions Functions
}

// registeredModules holds all of the modules that call the Register function
var registeredModules = make(map[string]*Module)

// Register creates a new module and adds it to the registered list
func Register(name string, functions Functions) *Module {
	m := new(Module)
	m.Name = name
	m.Functions = functions

	registeredModules[name] = m

	return m
}

// FindFunction finds a function based on a given module and name in our registered modules
func FindFunction(module string, name string) Function {
	mod, ok := registeredModules[module]
	if !ok {
		return nil
	}

	fun, ok := mod.Functions[name]
	if !ok {
		return nil
	}

	return fun
}
