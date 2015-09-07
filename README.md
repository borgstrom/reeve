Reeve
=====

/rēv/ -- The president of a village

Reeve is an RPC orchestration system, providing remote code execution and a event bus.  It provides
authentication and authorization using a system of identities and x509 certificates.


Theory / Notes
--------------

              [etcd]
                |
[client] -> [director] <--> [server1]
                        `-> [serverN]

reeve-director maintains connections to the servers, runs on at least 1 node

etcd maintains state, runs on all the director nodes (only accessible by directors)

reeve-server is the server, runs on all nodes

reeve is the client, used to interact with the servers, via the director


Reeve director nodes have persistent connections between each other to create a full mesh.  This
allows them to redirect and broadcast messages to each other.  When a director starts up it
registers itself in etcd.  Registrations are short and act like a heartbeat for all of the other
directors.  Directors watch the etcd key for registrations and expirations, when a registration
occurs it will ensure it's connected to the other director and when an expiration occurs it will
cause the director to release the connection.

Reeve server will connect to a random director upon start up.  The connection creates a record in
the state, binding that server to that director.  When the connection is closed the binding is
removed.  When a request comes to a director, it will first lookup if there's a binding for the
server(s) being targeted, if any servers are being handled by another director it will let that
director handle the communication with those servers.

The director to handle a request creates it in the state, but any director can update the request as
the servers they are bound to complete their parts in the request.


Security
--------

The security of etcd is paramount to the security of reeve, as it contains all of the private keys
and identity information for the network.  If etcd is compromised, reeve is compromised.  Thus, the
setup and securing of etcd is left as an exercise to the operator.

[//]: # vim: set ft=markdown tw=100 wrap spell :
