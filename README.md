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

Reeve director listens on one port: 4195


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

[//]: # vim: set ft=markdown tw=100 wrap spell :
