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
	"fmt"
	"net"

	log "github.com/Sirupsen/logrus"
)

type ServerConnection struct {
	Conn  net.Conn
	Proto *RawProtocol
}

func NewServerConnection(conn net.Conn, proto *RawProtocol) *ServerConnection {
	c := new(ServerConnection)

	c.Conn = conn
	c.Proto = proto

	return c
}

type Server struct {
	address string
}

func NewServer(host string, port int) *Server {
	s := new(Server)

	s.address = fmt.Sprintf("%s:%d", host, port)

	return s
}

func (s *Server) Listen(connections chan *ServerConnection) {
	log.WithFields(log.Fields{
		"address": s.address,
	}).Print("Listening")

	listener, err := net.Listen("tcp", s.address)
	if err != nil {
		log.WithFields(log.Fields{
			"error":   err,
			"address": s.address,
		}).Fatal("Failed to listen")
	}
	defer listener.Close()

	for {
		conn, _ := listener.Accept()
		log.WithFields(log.Fields{
			"address": conn.RemoteAddr().String(),
		}).Debug("New connection")

		connections <- NewServerConnection(conn, NewRawProtocol(conn))
	}
}
