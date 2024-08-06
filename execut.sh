killall bf_switchd
killall run_switchd

/home/admin12/bf-sde-9.12.0/run_switchd.sh -p reproPCAP &
sleep 20


#Config PORTS
/home/admin12/bf-sde-9.12.0/run_bfshell.sh -f portConfig.txt 

#Config Registers
/home/admin12/bf-sde-9.12.0/run_bfshell.sh -b loading2.py 

sleep 10

#Install RULES
nohup python3 tableEntries.py > log &

#rate-show
/home/admin12/bf-sde-9.12.0/run_bfshell.sh -f view

#python3 -m p4runtime_sh --grpc-addr 127.0.0.1:9090 \
#  --device-id 0 --election-id 0,1 --config <p4info.txt>,<pipeline config>

killall bf_switchd
