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

type ModuleFunction interface{}

type ModuleFunctions map[string]ModuleFunction

type Module struct {
	Name      string
	Functions ModuleFunctions
}

var registeredModules = make(map[string]*Module)

// Register creates a new module and adds it to the registered list
func Register(name string, functions ModuleFunctions) *Module {
	m := new(Module)
	m.Name = name
	m.Functions = functions

	registeredModules[name] = m

	return m
}

func FindFunction(module string, name string) ModuleFunction {
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
