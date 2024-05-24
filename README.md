# P4 Replay (P4R): Reproducing Packet Traces and Stateful Connections at Line-Rate on Your P4-based Switch

⚠️**This repository is in state of development**

## About P4R:

P4 Replay (P4R) is as a high-end traffic generation tool able to reproduce real world traffic scnearios. P4R benefits from the Tofino traffic generation capabilities to replicate real-world traffic patterns while maintaining high performance and accuracy. The user/network tester can use P4R to reproduce pre-captured traces (i.e., PCAPs) and create stateful TCP connections at the Tofino line rate. 

### P4R Opetation Modes
P4R can be used in three configuration modes: client, server, or internal (See Figure Below). In client mode , P4R can reproduce PCAPs or establish TCP connections with a connected server; in server mode, P4R responds to TCP connections from connected clients; and in internal mode , P4R can send packet traces or TCP connections to test.


#### Client mode. 
In this mode, P4R can instantiate clients to send traffic (i.e., packet traces) or establish stateful TCP connections with external servers. 

#### Server mode. 
In this mode, P4R will act as a stateful TCP server (e.g., iperf) and establish connections with multiple clients.

#### Internal mode. 
In this mode, the traffic generated by P4R is internally routed to a user’s P4 code running in parallel in another pipeline. In this mode, the user’s P4 code is responsible for correctly processing and routing the generated traffic.


## Requiriments

- git
- python3
- Tofino Switch™, SDE version 9.12+.

## Installation
```terminal
$ git clone https://github.com/ntrig-unicamp/P4R/.git
```
## Usage
