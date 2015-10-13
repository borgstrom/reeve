Reeve
=====

/rēv/ -- The president of a village

Reeve is an RPC orchestration system, providing remote code execution and a event bus.  It provides
authentication and authorization using a system of identities and x509 certificates.


Here be dragons
---------------

This is pre-alpha state right now.  It probably doesn't even run correctly at this point in time and
everything is subject to change.

There are a LOT of "TODO" notes throughout the code that also need to be reviewed.


Theory / Notes
--------------

```
              [etcd]
                |
[client] -> [director] <--> [agent1]
                        `-> [agentN]

```

reeve-director maintains connections to the servers, runs on at least 1 node

etcd maintains state, runs on all the director nodes (only accessible by directors)

reeve-agent is what executes code on behalf of the directors, runs on all nodes

reeve is the client, used to interact with the servers, via the director

Reeve director handles RPC on port 4195 and the event bus on 4196.


Reeve director nodes have persistent connections between each other to create a full mesh.  This
allows them to redirect and broadcast messages to each other.  When a director starts up it
registers itself in etcd.  Registrations are short and act like a heartbeat for all of the other
directors.  Directors watch the etcd key for registrations and expirations, when a registration
occurs it will ensure it's connected to the other director and when an expiration occurs it will
cause the director to release the connection.

Reeve agent will connect to a random director upon start up.  The connection creates a record in
the state, binding that agent to that director.  When the connection is closed the binding is
removed.  When a request comes to a director, it will first lookup if there's a binding for the
agent(s) being targeted, if any agents are being handled by another director it will let that
director handle the communication with those agents.

The director to handle a request creates it in the state, but any director can update the request as
the agents they are bound to complete their parts in the request.

The agents starts up and will generate its keypair, if it doesn't exist.  

Security
--------

The security of etcd is paramount to the security of reeve, as it contains all of the private keys
and identity information for the network.  If etcd is compromised, reeve is compromised.  Thus, the
setup and securing of etcd is left as an exercise to the operator.


Raw Protocol
------------

The Raw Protocol is what is used to exchange keys and prepare a session for TLS, prior to starting
the RPC mechanism on port 4195.  

It is a string based protocol that uses null bytes (`\x00`) to separate strings. 

The flow arrows in the following section represent: agent -> director

```
<- protocol token
<- protocol version
```

If the agent speaks the same protocol version the conversation continues, otherwise the agent
disconnects.

If the agent doesn't have a signed certificate it will indicate that it's sending a signing request,
and then send the PEM encoded request.

```
-> csr
-> PEM bytes
```

The server will inspect the request and see if it has a signed certificate for the client.  If it
doesn't it will simply respond with an ack, at which point the client can wait and try to send the
signing request again later.

```
<- ack
```

If the identity has been signed by the CA it will indicate that there's a signed certificate and
send the PEM encoded certificate followed by the PEM encoded CA certificate.

```
<- res
<- PEM bytes
<- PEM bytes
```

At this point the client has everything it needs to move on to TLS setup, and it indicates so.  If
the client has a signed certificate when it connects it can move directly to this step.

```
-> tls
```

The server will then upgrade the connection to mutual auth TLS and RPC will be started.

At the same time the client must open a connection to the event bus on port 4196.   This connection
is TLS by default and there is no key exchange.

To ensure the event bus has been setup correctly the server will send an initializer event over the
bus with a random number following connection.  The agent must call a verifier RPC with this number
or the director will close both connections.

### Command RPC

The Command RPC implementation is served by agents to directors when they connect on the main port.
It exposes all of the module functionality on that agent so that the director may invoke module
functions.

### Control RPC

The Control RPC implementation is served by directors to agents after they connect on the main port
plus 1.  It exposes the master event bus and agent management functions to the agent.

### Director to Director

When directors connect to each other they also use port 4195.  There is no automatic certificate
exchange for directors (they have access to etcd, and can sign their own certs), and instead of
issuing a command to start tls as an agent they announce they are a director and then upgrade to
TLS.

```
<- protocol token
<- protocol version
-> dir
```


/dev/urandom
============

Releases will be named after condiments. First versions to be ketchup, dijon, and miso.
Lots of ideas: https://en.wikipedia.org/wiki/List_of_condiments

Helpful resources
-----------------

* https://gist.github.com/artyom/6897140
* http://stackoverflow.com/questions/13110713/upgrade-a-connection-to-tls-in-go
* https://github.com/coreos/etcd-ca



[//]: # vim: set ft=markdown tw=100 wrap spell :
