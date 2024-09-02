killall bf_switchd
killall run_switchd



bf_kdrv_mod_load $SDE_INSTALL

/$SDE/../tools/p4_build.sh files/P4R_Generated_Code.p4



/$SDE/run_switchd.sh -p P4R_Generated_Code &

sleep 30


#Config PORTS
/$SDE/run_bfshell.sh -f files/portConfig.txt 

#Config Registers
/$SDE/run_bfshell.sh -b files/P4R_Register_Entries.py 

sleep 10

#Install RULES
nohup python3 files/tableEntries.py > log &

#rate-show
/$SDE/run_bfshell.sh -f files/view



killall bf_switchd
