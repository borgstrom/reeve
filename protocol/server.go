/*
Reeve - server implementation

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
	"net"
)

type Server struct {
	address string
}

type ListenHandler func(net.Conn)

func NewServer(address string) *Server {
	s := new(Server)

	s.address = address

	return s
}

func (s *Server) String() string {
	return s.address
}

func (s *Server) Listen(handler ListenHandler) {
	listener, err := net.Listen("tcp", s.address)
	if err != nil {
		panic(err.Error())
	}
	defer listener.Close()

	connections := make(chan net.Conn)

	go func() {
		for connection := range connections {
			go handler(connection)
		}
	}()

	for {
		conn, _ := listener.Accept()
		connections <- conn
	}
}
