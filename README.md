*Alexandru Mihai, 323CA, alexandrumihai200913@gmail.com*

# Router Dataplane

Tasks Implemented: (ALL) Forwarding Process, Longest Prefix Match, ARP
Protocol, ICMP Protocol.

The router implementation follows the basic components of the
forwarding process, treating both IPv4 and ARP incoming packets
and further sending the packets to their correct hosts. In addition,
error handling and responsiveness to the router is assured through 
the ICMP protocol.

---

## Forwarding Process

Throughout this section, we verify the checksum of the incoming packet
and verify if the ttl becomes 0 or the packet receiver can be found
in the network. If the router is the destionation, we further call
ICMP request handler in order to send an echo reply message to the
host. If the router is not the destination, we are just forwarding
the packet and changing it's required field.

---

## Longest Prefix Match

In order to achieve an efficient complexity for searching the next
best route, the routing table was sorted with Merge Sort (which was
inspired by the Algorithm Design course [1]). Each next hop was
determined by binary searching the newly sorted routing table and
therefore each query is solved in *O(log N)* time complexity, thus
resulting in a total time complexity of *O(N log N)* for
constructing the sorted table and solving all inqueries.

---

## ARP Protocol

The ARP Protocol ensures the construction of the ARP table (in which
each IPv4 address is linked to a specific MAC address). If the MAC
destination for the required next hop cannot be found, we issue an
ARP request which will be floaded in the network through all the
routers' interfaces. The so called 'waiting' packet is transferred
into a waiting queue until we receive the necessary MAC destination
address to send the packets. A router can receive either an ARP
request from another router, which would determine to forward its
MAC address if it is the inquires host or an ARP reply after finding
the inquired information. After the ARP reply we can search through
the waiting queue to see which packets can now be forward and
redirrect them. 

---

## ICMP Protocol

The ICMP Protocol issues messages regarding responsiveness (echo and
reply) and error handling (for an expired time to live or an unfound
host in the network). Those two types of ICMP messages were treated
individually, completing each field on the ICMP protocol with the
required information, as well as ensuring that the payload is
correctly and completely placed. For the echo-reply messages the
router takes the payload from the original packet and copies it
after which it just forwards the newly build packet.

---

## Bibliography

[1] [Merge Sort and Binary Search](https://ocw.cs.pub.ro/courses/pa/laboratoare/laborator-01)