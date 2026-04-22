from netaddr import IPAddress

# Reference the specific P4 pipeline (reproPCAP)
p4 = bfrt.reproPCAP.pipe

# Access the 'recirc' register located in the Ingress control block
recirc = p4.SwitchIngress.recirc

# Add entry to the recirculation register
# REGISTER_INDEX=0: The position in the register array
# f1=1: Sets the value to 1 for recirculation
recirc.add(REGISTER_INDEX=0, f1=1)

# Ensure all pending table and register operations are fully pushed to the hardware
# This synchronizes the control plane state with the ASIC/Switch data plane
bfrt.complete_operations()
