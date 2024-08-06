from scapy.all import *
import sys

script = open("configuration_file.py", "w")




script.write("from netaddr import IPAddress\n")
script.write("p4 = bfrt.reproPCAP.pipe\n")
script.write("\n")
script.write("def clear_all(verbose=True, batching=True):\n")
script.write("	global p4\n")
script.write("	global bfrt\n")

script.write("	for table_types in (['MATCH_DIRECT', 'MATCH_INDIRECT_SELECTOR'],\n")
script.write("                      ['SELECTOR'],\n")
script.write("                      ['ACTION_PROFILE']):\n")
script.write("		for table in p4.info(return_info=True, print_info=False):\n")
script.write("			if table['type'] in table_types:\n")
script.write("				if verbose:\n")
script.write('					print("Clearing table {:<40} ... ".\n')
script.write("						format(table['full_name']), end='', flush=True)\n")
script.write("				table['node'].clear(batch=batching)\n")
script.write("				if verbose:\n")
script.write("					print('Done')\n\n")

script.write("clear_all(verbose=True)\n\n")



script.write("\n\ntime = p4.SwitchIngress.timer\n")
script.write("index = p4.SwitchIngress.counter\n\n")

#script.write("index.add(REGISTER_INDEX=0,f1=0)\n\n\n")

#mirroring
script.write("mir = bfrt.mirror\n\n")

script.write("get_sid = p4.SwitchIngress.packet_size\n\n")






script.write("storage1 = p4.SwitchIngress.storage1\n")
script.write("storage2 = p4.SwitchIngress.storage2\n")
script.write("storage3 = p4.SwitchIngress.storage3\n")
script.write("storage4 = p4.SwitchIngress.storage4\n")
script.write("storage5 = p4.SwitchIngress.storage5\n")
script.write("storage6 = p4.SwitchIngress.storage6\n")
script.write("storage7 = p4.SwitchIngress.storage7\n")
script.write("storage8 = p4.SwitchIngress.storage8\n")
script.write("storage9 = p4.SwitchIngress.storage9\n")
script.write("storage10 = p4.SwitchIngress.storage10\n")
script.write("storage11 = p4.SwitchIngress.storage11\n")
script.write("storage12 = p4.SwitchIngress.storage12\n")
script.write("storage13 = p4.SwitchIngress.storage13\n")
script.write("storage14 = p4.SwitchIngress.storage14\n")
script.write("storage15 = p4.SwitchIngress.storage15\n")
script.write("storage16 = p4.SwitchIngress.storage16\n")
script.write("storage17 = p4.SwitchIngress.storage17\n")
script.write("storage18 = p4.SwitchIngress.storage18\n")
script.write("storage19 = p4.SwitchIngress.storage19\n")
script.write("storage20 = p4.SwitchIngress.storage20\n")
script.write("storage21 = p4.SwitchIngress.storage21\n")
script.write("storage22 = p4.SwitchIngress.storage22\n")
script.write("storage23 = p4.SwitchIngress.storage23\n")
script.write("storage24 = p4.SwitchIngress.storage24\n")
script.write("storage25 = p4.SwitchIngress.storage25\n")
script.write("storage26 = p4.SwitchIngress.storage26\n")
script.write("storage27 = p4.SwitchIngress.storage27\n")
script.write("storage28 = p4.SwitchIngress.storage28\n")
script.write("storage29 = p4.SwitchIngress.storage29\n")
script.write("storage30 = p4.SwitchIngress.storage30\n")





script.write("\n\n#loading packets:\n\n")










# Nome do arquivo .pcap a ser lido
#pcap_file = "testing.pcap"

pcap_file = sys.argv[1]


# Lendo o arquivo .pcap
packets = rdpcap(pcap_file)

previous_packet_time = packets[0].time


# Lista para armazenar os tamanhos dos pacotes
packet_sizes = []

# Iterando sobre cada pacote
for i, packet in enumerate(packets):

	# Calculando o tamanho do pacote
	packet_size = len(packet)
    # Adicionando o tamanho do pacote à lista
	packet_sizes.append(packet_size)


	# Calculando o tempo desde o último pacote
	time_since_previous = packet.time - previous_packet_time

	time_since_previous_ns = (packet.time - previous_packet_time) * 1e9

    # Atualizando o tempo do pacote anterior para o tempo deste pacote
	previous_packet_time = packet.time
    
	# Obtendo os primeiros 120 bytes do pacote
	packet_data = bytes(packet)[:120]
    
	script.write(f"\n#packet{i}: \n")

	#new
	formatted_data = [packet_data[i:i+4].hex() for i in range(0, len(packet_data), 4)]
    
    # Iterando sobre cada palavra de 4 bytes e adicionando ao storage correspondente
	for j, word in enumerate(formatted_data):
        # Construindo o comando para adicionar ao storage
		if len(word) == 4 :
			command = f"storage{j+1}.add(REGISTER_INDEX={i}, f1=0x{word}0000)\n"
		else:	
			command = f"storage{j+1}.add(REGISTER_INDEX={i}, f1=0x{word})\n"
        # Imprimindo o comando
		script.write(command)
		#print(command)

	script.write(f"time.add(REGISTER_INDEX={i}, f1={time_since_previous_ns:.0f})\n\n")

# Ao final, contando o número de tamanhos diferentes que existem no PCAP
#unique_sizes = len(set(packet_sizes))
#print(f"Número de tamanhos diferentes no PCAP: {unique_sizes}")
#print(packet_sizes)



#mirror sessions and table entries


# Dicionário para associar 'i' a 'number+1'
packetSize_to_sid = {}

for number, i in enumerate(set(packet_sizes)):
	script.write(f"mir.cfg.entry_with_normal( sid = {number+1}, direction = 'BOTH', session_enable = True, ucast_egress_port = 130, ucast_egress_port_valid = 1, max_pkt_len = {i+30}).push()\n")
	packetSize_to_sid[i] = number + 1


print(packetSize_to_sid[66])

script.write("\n\n")

for i, element in enumerate(packet_sizes):
	script.write(f"get_sid.add_with_getSid(position={i}, correct = {packetSize_to_sid[element]})\n")


#get_sid.add_with_getSid(position=1, correct = 10)



script.write("\nindex.add(REGISTER_INDEX=0,f1=0)\n\n\n")
script.write("recirc = p4.SwitchIngress.recirc\n")
script.write("recirc.add(REGISTER_INDEX=0,f1=0)\n\n")

script.write("\n\nbfrt.complete_operations()\n")

script.close()

