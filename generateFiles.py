from scapy.all import *
import sys


def write_cleanup_logic(script):
    """
    Generates a cleanup function within the output script.
    Ensures the Tofino pipeline is cleared of previous entries before execution.
    """
    script.write("def clear_all(verbose=True, batching=True):\n")
    script.write("    global p4\n")
    script.write("    global bfrt\n")
    script.write("    # Iterating through different table types to ensure a clean state\n")
    script.write("    for table_types in (['MATCH_DIRECT', 'MATCH_INDIRECT_SELECTOR'],\n")
    script.write("                        ['SELECTOR'],\n")
    script.write("                        ['ACTION_PROFILE']):\n")
    script.write("        for table in p4.info(return_info=True, print_info=False):\n")
    script.write("            if table['type'] in table_types:\n")
    script.write("                if verbose:\n")
    script.write('                    print("Clearing table {:<40} ... ".\n')
    script.write("                        format(table['full_name']), end='', flush=True)\n")
    script.write("                table['node'].clear(batch=batching)\n")
    script.write("                if verbose:\n")
    script.write("                    print('Done')\n\n")
    script.write("clear_all(verbose=True)\n\n")



def generate_configuration(pcap_file, egress_port):
    """
    Parses the input PCAP and generates the 'configuration_file.py'
    containing BFRT commands for the Intel Tofino ASIC.
    """
    # Loading packets from PCAP
    packets = rdpcap(pcap_file)
    previous_packet_time = packets[0].time
    packet_sizes = []

    with open("configuration_file.py", "w") as script:
        # Header and Initialization
        script.write("from netaddr import IPAddress\n")
        script.write("p4 = bfrt.reproPCAP.pipe\n\n")
        
        write_cleanup_logic(script)

        # Control Plane Object References
        script.write("time = p4.SwitchIngress.timer\n")
        script.write("index = p4.SwitchIngress.counter\n")
        script.write("mir = bfrt.mirror\n")
        script.write("get_sid = p4.SwitchIngress.packet_size\n\n")

        # Register Storage Definitions (30 registers of 32-bits each)
        for s in range(1, 31):
            script.write(f"storage{s} = p4.SwitchIngress.storage{s}\n")

        script.write("\n# Loading packet data into registers:\n")

        # Packet Processing Loop
        for i, packet in enumerate(packets):
            packet_size = len(packet)
            packet_sizes.append(packet_size)

            # Timing calculation (nanoseconds)
            time_since_previous_ns = (packet.time - previous_packet_time) * 1e9
            previous_packet_time = packet.time
            
            # Payload extraction (First 120 bytes)
            packet_data = bytes(packet)[:120]
            formatted_data = [packet_data[j:j+4].hex() for j in range(0, len(packet_data), 4)]
            
            script.write(f"\n# Packet {i} Configuration\n")
            for j, word in enumerate(formatted_data):
                # Ensure 32-bit alignment
                val = f"0x{word}0000" if len(word) == 4 else f"0x{word}"
                script.write(f"storage{j+1}.add(REGISTER_INDEX={i}, f1={val})\n")

            script.write(f"time.add(REGISTER_INDEX={i}, f1={time_since_previous_ns:.0f})\n")

        # Mirroring and Session ID (SID) mapping
        unique_sizes = (set(packet_sizes))
        packetSize_to_sid = {}

        script.write("\n# Mirror session configuration\n")
        for number, size in enumerate(unique_sizes):
            sid = number + 1
            # Add 24 bytes for L1/L2 overhead (Preamble/CRC)
            script.write(f"mir.cfg.entry_with_normal(sid={sid}, direction='BOTH', session_enable=True, "
                         f"ucast_egress_port={egress_port}, ucast_egress_port_valid=1, "
                         f"max_pkt_len={size + 24}).push()\n")
            packetSize_to_sid[size] = sid

        script.write("\n# Mapping packets to SIDs\n")
        for i, size in enumerate(packet_sizes):
            script.write(f"get_sid.add_with_getSid(position={i}, correct={packetSize_to_sid[size]})\n")

        # Finalize pipeline state
        script.write("\nindex.add(REGISTER_INDEX=0, f1=0)\n")
        script.write("recirc = p4.SwitchIngress.recirc\n")
        script.write("recirc.add(REGISTER_INDEX=0, f1=0)\n")
        script.write("\nbfrt.complete_operations()\n")
        


if __name__ == "__main__":
    # Basic Argument Validation
    if len(sys.argv) < 3:
        print("Usage: python3 generateFiles.py <pcap_file> <egress_port>")
        sys.exit(1)

    input_pcap = sys.argv[1]
    target_port = sys.argv[2]

    generate_configuration(input_pcap, target_port)
    print(f"Success: 'configuration_file.py' has been generated.")