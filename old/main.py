from src.data import *

myTG = P4RGenerator()                             	#instatiate the traffic generator

myTG.defineGenerationPort(68)                         	#define ID of the generation port
myTG.definePipeline(1)				      	#define the pipeline that P4R will run

myTG.addOutputPort(5, 160, "10G")                 	#physical port, port ID(D_P), portBW
myTG.generationMode("Client-PCAP")		  	#define the operation mode
myTG.setPCAP("myPCAP_example.pcap", timestamp = True)	#define how the pcap will be reproduced, in this case following the timestamps

myTG.generate()						#generate the files


