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
)

type ConnectHandler func(*Protocol) error

// Creates a new Client and dials the director.  Director should be in the form <host>:<port>
func Connect(director string, port int, handler ConnectHandler) error {
	address := fmt.Sprintf("%s:%d", director, port)
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return err
	}
	defer conn.Close()

	proto := NewProtocol(conn)
	proto.SetServerName(director)
	return handler(proto)
}
