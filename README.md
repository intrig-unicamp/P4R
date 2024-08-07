# P4 Replay (P4R): Reproducing Packet Traces and Stateful Connections at Line-Rate on Your P4-based Switch

⚠️**This repository is in a state of development**

[Update Aug]: We are improving the user interface, and some functionalities are not yet available in the interface (Just hard code).

___
<p align="center">
  To keep updated about this project, please don't forget to star ⭐️ the repository.
</p>

___


## About P4R:

P4 Replay (P4R) is as a high-end traffic generation tool able to reproduce real world traffic scnearios. P4R benefits from the Tofino traffic generation capabilities to replicate real-world traffic patterns while maintaining high performance and accuracy. The user/network tester can use P4R to reproduce pre-captured traces (i.e., PCAPs) and create stateful TCP connections at the Tofino line rate.

![Alt text](https://github.com/intrig-unicamp/P4R/blob/main/images/figure_1.png) 

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
- Tofino Switch™, SDE version 9.13+.

## Installation
```terminal
$ git clone https://github.com/ntrig-unicamp/P4R/.git
```
## Usage

After clone our repository, you should acess the P4R directory and modify the file main.py. In this file you can configure you traffic patterns, desired output ports, and all other necessary parameters to start the traffic generation. P4R will use your definitions to generate all configuration files and execution scripts, and after that you can start the traffic generation. Below we provide a description of available commands, parameters and how to use them.

### Getting started
First you need to define the traffic genrator object:

```python
NameTrafficGenerator = P4RGenerator()
  #instatiate the traffic generator with the name "NameTrafficGenerator"
```
Then you need to define some configurations parameters, independently of the used mode. This parameters allow P4R correctly configure traffic generation in the appropriate pipeline and ports.
```python
NameTrafficGenerator.addGenerationPort(port) #port (generation port ID on Tofino)
NameTrafficGenerator.definePipeline(1)
```

⚠️ Make sure that your defined generation port are in the defined pipeline. Furthermore, the ports to which you want to send the generated traffic must also be part of this same pipeline. For more information about pipelines and ports, please read the official Tofino switch documentation.

After that, you can define the output port to send the generated traffic:


```python
NameTrafficGenerator.addOutputPort(port, channel, bw)
  #port (physical port)
  #channel (port ID(D_P))
  #bw (portBW)
```

ℹ️ In case of using internal mode, the output port does not need to be defined, and you should replace the port parameter with the ID of the recirculation port in the other pipeline.

### Functionalities
After the basic configurations, you can start exploring P4R's features to generate traffic according to your needs. Below we list the available commands, and how to use them.

Defining the operation mode:
```python
NameTrafficGenerator.generationMode(mode)		  	#define the operation mode, the modes can be "Client-PCAP, Client-TCP, Server-TCP, Internal" 
```

Defining the PCAP file:
```python
#set the PCAP file to be sent, the parameters are the Pcap file, timestamp is a bool that define if the reproduction will follow the original timestamps, and if this boolean is false, the pcap will be repeated and you can definen a desired throughput in the last parameter.
NameTrafficGenerator.setPCAP("PCAP_FILE.pcap", timestamp, throughput)
```
⚠️ Note that if the timestamp parameters is set to true, the throughput cannot be defined.


Creating a TCP flow:
```python
NameTrafficGenerator.addTCPFlow(eth_src, eth_dst, ip_src, ip_dst, port_src, port_dst, window)		  	#add a new TCP flow to be started 
```
Creating a TCP server:
```python
myTG.addTCPServer(eth_addr, ip_addr, port, window)
```

## Examples
Next we provide some simple examples how to use P4R. 


### Reproducing a PCAP file using the timestamp mode
```python

myTG = P4RGenerator()                    	#instatiate the traffic generator

myTG.defineGenerationPort(68)            	#define ID of the generation port
myTG.definePipeline(1)				      	    #define the pipeline that P4R will run

myTG.addOutputPort(5, 160, "10G")         #physical port, port ID(D_P), portBW
myTG.generationMode("Client-PCAP")		  	#define the operation mode

#define how the pcap will be reproduced, in this case following the timestamps
myTG.setPCAP("myPCAP_example.pcap", timestamp = True)	

myTG.generate()	
```
### Creating a TCP connection in Client Mode
```python

myTG = P4RGenerator()                    	#instatiate the traffic generator

myTG.defineGenerationPort(68)            	#define ID of the generation port
myTG.definePipeline(1)				      	    #define the pipeline that P4R will run

myTG.addOutputPort(5, 160, "10G")         #physical port, port ID(D_P), portBW
myTG.generationMode("Client-TCP")		  	#define the operation mode

#Creating a TCP flow with a window size of 1 packet of 1500 bytes
myTG.addTCPFlow("11:11:11:11:11:11", "22:22:22:22:22:22", "192.168.0.1", "192.168.0.2", 3000, 5001, 1)

myTG.generate()	
```
### Using P4R in the TCP server mode
```python

myTG = P4RGenerator()                    	#instatiate the traffic generator

myTG.defineGenerationPort(68)            	#define ID of the generation port
myTG.definePipeline(1)				      	    #define the pipeline that P4R will run

myTG.addOutputPort(5, 160, "10G")         #physical port, port ID(D_P), portBW
myTG.generationMode("Server-TCP")		  	#define the operation mode

#Creating a TCP server with a window size of 1 packet of 1500 bytes
myTG.addTCPServer("11:11:11:11:11:11", "192.168.0.2", 3000, 1)

myTG.generate()	
```


