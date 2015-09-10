// Reeve server implementation
//
// Copyright 2015 Evan Borgstrom
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"bufio"
	"fmt"
	"net"

	log "github.com/Sirupsen/logrus"
)

type Client struct {
	conn     net.Conn
	server   *Server
	incoming chan string
}

func NewClient(conn net.Conn, server *Server) *Client {
	c := new(Client)
	c.conn = conn
	c.server = server
	return c
}

func (c *Client) listen() {
	reader := bufio.NewReader(c.conn)
	for {
		// TODO: make this non line based
		_, err := reader.ReadString('\n')
		if err != nil {
			c.conn.Close()
			// TODO: handle connection closed
			return
		}

		// TODO: handle message
	}
}

func (c *Client) Send(message string) error {
	_, err := c.conn.Write([]byte(message))
	return err
}

type Server struct {
	address  string
	clients  []*Client
	incoming chan net.Conn
}

func NewServer(host string, port int) *Server {
	s := new(Server)

	s.address = fmt.Sprintf("%s:%d", host, port)

	return s
}

func (s *Server) Listen() {
	log.WithFields(log.Fields{
		"address": s.address,
	}).Print("Listening")

	go s.handleIncoming()

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
		s.incoming <- conn
	}
}

func (s *Server) handleIncoming() {
	for {
		select {
		case conn := <-s.incoming:
			s.newClient(conn)
		}
	}
}

func (s *Server) newClient(conn net.Conn) {
	client := NewClient(conn, s)

	// Protocol exchange

	// Key exchange

	go client.listen()
}
