killall bf_switchd
killall run_switchd

/$SDE/../../tools/p4_build.sh reproPCAP.p4


/$SDE/run_switchd.sh -p reproPCAP &
sleep 30


#Config PORTS (need to be adjusted according to your environment)
/$SDE/run_bfshell.sh -f portConfig.txt 

#Config Registers, sending the PCAP information
/$SDE/run_bfshell.sh -b configuration_file.py 

sleep 10

#Install table entries for traffic generation, starting to generate template packets
nohup python3 tableEntries.py > log &

#restart the CLI for monitor the ports throughput
/$SDE/run_bfshell.sh -f view


#to start the generation, run in another terminal
#/$SDE/run_bfshell.sh -b Start.py 

killall bf_switchd
killall run_switchd
