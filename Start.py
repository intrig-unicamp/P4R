
from netaddr import IPAddress
p4 = bfrt.reproPCAP.pipe



recirc = p4.SwitchIngress.recirc
recirc.add(REGISTER_INDEX=0,f1=1)

bfrt.complete_operations()
