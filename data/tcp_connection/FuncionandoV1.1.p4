#include <tna.p4>

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

const bit<16> ETHERTYPE_IPV4 = 0x0800;


header ethernet_h {
	mac_addr_t dst_addr;
	mac_addr_t src_addr;
	bit<16> ether_type;
}

header ipv4_h {
	bit<4> version;
	bit<4> ihl;
	bit<8> diffserv;
	bit<16> total_len;
	bit<16> identification;
	bit<3> flags;
	bit<13> frag_offset;
	bit<8> ttl;
	bit<8> protocol;
	bit<16> hdr_checksum;
	ipv4_addr_t src_addr;
	ipv4_addr_t dst_addr;
}

header tcp_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}




header tcp_nop_h {
    bit<8>   nop1;
    bit<8>   nop2;
}



header tcp_nop2_h {
    bit<8>   nop1;
}


header tcp_mss_h {
    bit<8> kind;
	bit<8> length;
	bit<16> mssValue;
}

header tcp_sack_h {
    bit<8>  kind;
    bit<8>  lenght;
}



header tcp_timestamp_h{
    bit<8>   kind;
    bit<8>   length;
    bit<32>  tsval_in;
    bit<32>  tsval_out;
    //bit<16>  tsecr_msb;
    //bit<16>  tsecr_lsb;
}

header window_scale_h{
	bit<8>		kind;
    bit<8>		length;
	bit<8>		shift;	
}

header extraBytes_h{
	bit<32> pad1;
	bit<32> pad2;
	bit<32> pad3;
	bit<32> pad4;
	bit<32> pad5;

}





struct headers {
	//mirror_bridged_metadata_h bridged_md;
	pktgen_timer_header_t     	timer;
	pktgen_port_down_header_t 	port_down;
	ethernet_h    				ethernet;
	ipv4_h						ipv4;
	tcp_h						tcp;
	//extraBytes_h				extraBytes;  //header added to parse extra bytes included in packet generation. It happens because the minimum size of generated packets are n
	tcp_nop_h           		nop;
    tcp_mss_h		      		mss;
	tcp_sack_h  	    		sack;
    tcp_timestamp_h     		timestamp;
	tcp_nop2_h           		nop_half;
	window_scale_h		 		win_scale;
	//rec_h		rec;
	//data_t		data;
}

struct metadata_storage_t{

	bit<32> position;
	bit<16> recirculating;
	bit<32> ackNo;
	bit<32> seqNo;
	bit<1> mirrorS;
	MirrorId_t session_ID;
	//mirror_type_t  test; 
	bit<16> checksum;
	bit<8> realTCP;
	bit<1> ipv4Check;
	bit<1> tcpCheck;
	bit<16> tcpLength;
	bit<8> checksumType;
	bit<32> timeAux;
		

}

header extra_t {
	bit<32> ext1;
	bit<32> ext2;
	bit<32> ext3;
	bit<32> ext4;
	bit<32> ext5;
	bit<32> ext6;
	bit<32> ext7;
	bit<16> ext8;
}

struct headers_2 {
	extra_t extra;
}


parser SwitchIngressParser(
	packet_in packet, 
	out headers hdr, 
	out metadata_storage_t md, 
	out ingress_intrinsic_metadata_t ig_intr_md) {


	Checksum() tcp_checksum;

	state start {
		packet.extract(ig_intr_md);
		packet.advance(PORT_METADATA_SIZE);

		pktgen_timer_header_t pktgen_pd_hdr = packet.lookahead<pktgen_timer_header_t>();
		transition select(pktgen_pd_hdr.app_id) {
			1 : parse_fin;
			2 : parse_pktgen_timer;
			3 : parse_generated_packet2;//tentando-desespero
			4 : parse_pktgen_port_down;
			5 : parse_generated_packet;
			6 : parse_initial_syn;
			7 : parse_manual_push;
			default : parse_ethernet;
		}
	}

	state parse_pktgen_timer {
		//packet.extract(hdr.timer);
		transition parse_ethernet;
	}


	//state to parse all necessary field of a initial syn packet
	state parse_initial_syn {
		//packet.extract(hdr.timer);

		packet.extract(hdr.ethernet);

		packet.extract(hdr.ipv4);

		packet.extract(hdr.tcp);

		packet.extract(hdr.mss);
		packet.extract(hdr.sack);
		packet.extract(hdr.timestamp);
		packet.extract(hdr.nop_half);
		packet.extract(hdr.win_scale);

		md.realTCP = 1;


		transition accept;
	}


	state parse_fin{
	
		packet.extract(hdr.ethernet);

		packet.extract(hdr.ipv4);

		tcp_checksum.subtract({hdr.ipv4.src_addr});
		tcp_checksum.subtract({hdr.ipv4.dst_addr});
		tcp_checksum.subtract({hdr.ipv4.total_len});


		packet.extract(hdr.tcp);

		tcp_checksum.subtract({hdr.tcp.checksum});
		tcp_checksum.subtract({hdr.tcp.srcPort, hdr.tcp.dstPort});
		tcp_checksum.subtract({hdr.tcp.seqNo, hdr.tcp.ackNo});
		tcp_checksum.subtract({hdr.tcp.dataOffset, hdr.tcp.res, hdr.tcp.ecn, hdr.tcp.ctrl});
		tcp_checksum.subtract({hdr.tcp.window, hdr.tcp.urgentPtr});


		packet.extract(hdr.nop);
		
		tcp_checksum.subtract({hdr.nop.nop1, hdr.nop.nop2});



		packet.extract(hdr.timestamp);

		tcp_checksum.subtract({hdr.timestamp.kind, hdr.timestamp.length, hdr.timestamp.tsval_in, hdr.timestamp.tsval_out});


		tcp_checksum.subtract_all_and_deposit(md.checksum);

			
		md.realTCP = 3;
		md.checksumType = 22;

		transition accept;
	
	}



	state parse_pktgen_port_down {
		packet.extract(hdr.port_down);
		transition reject;
	}

	state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            //ETHERTYPE_ARP:  parse_arp;
            0x800:  parse_ipv4;
            default: accept;
        }
    }


	state parse_generated_packet2 {

		packet.extract(hdr.timer);
		md.realTCP = 3;
		transition accept;


	}


	state parse_generated_packet {

		//packet.extract(hdr.timer); //n sei se precisa ou n


		packet.extract(hdr.ethernet);
		packet.extract(hdr.ipv4);

		
		tcp_checksum.subtract({hdr.ipv4.src_addr});
		tcp_checksum.subtract({hdr.ipv4.dst_addr});
		tcp_checksum.subtract({hdr.ipv4.total_len});

		packet.extract(hdr.tcp);

		md.realTCP = 3;
		//md.checksumType = 22;


		tcp_checksum.subtract({hdr.tcp.checksum});
		tcp_checksum.subtract({hdr.tcp.srcPort, hdr.tcp.dstPort});
		tcp_checksum.subtract({hdr.tcp.seqNo, hdr.tcp.ackNo});
		


		tcp_checksum.subtract({hdr.tcp.dataOffset, hdr.tcp.res, hdr.tcp.ecn, hdr.tcp.ctrl});
		tcp_checksum.subtract({hdr.tcp.window, hdr.tcp.urgentPtr});
		




		packet.extract(hdr.nop);

		tcp_checksum.subtract({hdr.nop.nop1, hdr.nop.nop2});
		
		packet.extract(hdr.timestamp);

		tcp_checksum.subtract({hdr.timestamp.kind, hdr.timestamp.length, hdr.timestamp.tsval_in, hdr.timestamp.tsval_out});

		

		tcp_checksum.subtract_all_and_deposit(md.checksum);

		transition accept;

	}


	state parse_manual_push {

		packet.extract(hdr.ethernet);
		packet.extract(hdr.ipv4);
		
		tcp_checksum.subtract({hdr.ipv4.src_addr});
		tcp_checksum.subtract({hdr.ipv4.dst_addr});
		tcp_checksum.subtract({hdr.ipv4.total_len});

		packet.extract(hdr.tcp);

		md.realTCP = 3;
		md.checksumType = 22;

		tcp_checksum.subtract({hdr.tcp.checksum});
		tcp_checksum.subtract({hdr.tcp.srcPort, hdr.tcp.dstPort});
		tcp_checksum.subtract({hdr.tcp.seqNo, hdr.tcp.ackNo});

		tcp_checksum.subtract({hdr.tcp.dataOffset, hdr.tcp.res, hdr.tcp.ecn, hdr.tcp.ctrl});
		tcp_checksum.subtract({hdr.tcp.window, hdr.tcp.urgentPtr});

		packet.extract(hdr.nop);

		tcp_checksum.subtract({hdr.nop.nop1, hdr.nop.nop2});
		
		packet.extract(hdr.timestamp);

		tcp_checksum.subtract({hdr.timestamp.kind, hdr.timestamp.length, hdr.timestamp.tsval_in, hdr.timestamp.tsval_out});

		tcp_checksum.subtract_all_and_deposit(md.checksum);

		transition accept;
	}



	state parse_ipv4 {
        packet.extract(hdr.ipv4);


		//tentando resolver o ack
		tcp_checksum.subtract({hdr.ipv4.total_len});
		tcp_checksum.subtract({hdr.ipv4.src_addr});
		tcp_checksum.subtract({hdr.ipv4.dst_addr});
		//fim do teste


		/*tcp_checksum.subtract({hdr.ipv4.src_addr, hdr.ipv4.dst_addr,
                8w0,
                hdr.ipv4.protocol, hdr.ipv4.total_len});*/

        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
			2: parse_generated_tcp;
            default: accept;
        }
    }



    state parse_tcp {
        packet.extract(hdr.tcp);
      	md.realTCP = 1;

		/*tcp_checksum.subtract({hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.res,
                hdr.tcp.ecn,
                hdr.tcp.ctrl,
                hdr.tcp.window,
                hdr.tcp.urgentPtr});*/

		//tentando resolver o ack

		tcp_checksum.subtract({hdr.tcp.checksum});
		tcp_checksum.subtract({hdr.tcp.srcPort, hdr.tcp.dstPort});
		tcp_checksum.subtract({hdr.tcp.seqNo, hdr.tcp.ackNo});
		tcp_checksum.subtract({hdr.tcp.dataOffset, hdr.tcp.res, hdr.tcp.ecn, hdr.tcp.ctrl});
		tcp_checksum.subtract({hdr.tcp.window, hdr.tcp.urgentPtr});





		transition select(hdr.tcp.dataOffset) {
            ( 5 )  : parse_mss_sack;//accept;
			//( 6 )  : remove_extra;
            ( 8 ) : parse_nop;
            ( 10  ) : parse_mss_sack;
            default : accept;
        }


        //transition accept;
	}


	state parse_nop{
        packet.extract(hdr.nop);

		tcp_checksum.subtract({hdr.nop.nop1, hdr.nop.nop2});
		
		packet.extract(hdr.timestamp);

		tcp_checksum.subtract({hdr.timestamp.kind, hdr.timestamp.length, hdr.timestamp.tsval_in, hdr.timestamp.tsval_out});
		
		tcp_checksum.subtract_all_and_deposit(md.checksum);

        transition accept;
    }
    
    state parse_mss_sack{
        packet.extract(hdr.mss);
		packet.extract(hdr.sack);

		//tentando resolver o ack
		//tcp_checksum.subtract({hdr.ipv4.total_len});
		//tcp_checksum.subtract({hdr.ipv4.src_addr});
		//tcp_checksum.subtract({hdr.ipv4.dst_addr});
/*
		tcp_checksum.subtract({hdr.tcp.checksum});
		tcp_checksum.subtract({hdr.tcp.srcPort, hdr.tcp.dstPort});
		tcp_checksum.subtract({hdr.tcp.seqNo, hdr.tcp.ackNo});
		tcp_checksum.subtract({hdr.tcp.dataOffset, hdr.tcp.res, hdr.tcp.ecn, hdr.tcp.ctrl});
		tcp_checksum.subtract({hdr.tcp.window, hdr.tcp.urgentPtr});
*/


		tcp_checksum.subtract({hdr.mss.kind, hdr.mss.length, hdr.mss.mssValue});

		tcp_checksum.subtract({hdr.sack.kind, hdr.sack.lenght});


		//fim teste

	
		/*tcp_checksum.subtract({hdr.mss.kind,				//todos os options aq
				hdr.mss.length,				
				hdr.mss.mssValue,
				hdr.sack.kind,
				hdr.sack.lenght});*/

        transition parse_timestamp;//changed
    }

    state parse_timestamp{
        packet.extract(hdr.timestamp);
        //tcp_checksum.subtract({hdr.timestamp.tsecr_msb, hdr.timestamp.tsecr_lsb,hdr.timestamp.tsval_msb,hdr.timestamp.tsval_lsb});
        //meta.checksum = tcp_checksum.get();

		/*tcp_checksum.subtract({hdr.timestamp.kind,
				hdr.timestamp.length,
				hdr.timestamp.tsval_in,
      			hdr.timestamp.tsval_out});*/
	
        //transition accept;//changed


		//tentando resolver ack
		tcp_checksum.subtract({hdr.timestamp.kind, hdr.timestamp.length});

		tcp_checksum.subtract({hdr.timestamp.tsval_in, hdr.timestamp.tsval_out});

		//fim fo tentando



		transition parse_win_scale;
    }

	state parse_win_scale{
		
		packet.extract(hdr.nop_half);
		packet.extract(hdr.win_scale);
		


		//tentando resolver o ack

		tcp_checksum.subtract({hdr.nop_half.nop1});

		tcp_checksum.subtract({hdr.win_scale.kind, hdr.win_scale.length, hdr.win_scale.shift});


		tcp_checksum.subtract_all_and_deposit(md.checksum);
		//fim do teste


		transition accept;

	}



	state parse_generated_tcp {
        packet.extract(hdr.tcp);
      	md.realTCP = 0;
        transition accept;
	}



}


control SwitchIngressDeparser(
      packet_out pkt,
      inout headers hdr,
      in metadata_storage_t md,
      in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

	Mirror() mirror;

	Checksum() ipv4_checksum;
    Checksum() tcp_checksum;

	apply {
		
			//md.ipv4Check == 1 old
		if (hdr.ipv4.isValid()){
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
				hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
        }
        if (hdr.tcp.isValid()){


			if(hdr.nop_half.isValid()){
		        hdr.tcp.checksum = tcp_checksum.update({
		            hdr.ipv4.src_addr,
		            hdr.ipv4.dst_addr,
		            8w0,
		            hdr.ipv4.protocol,
					md.tcpLength,
		            hdr.tcp.srcPort,
		            hdr.tcp.dstPort,
		            hdr.tcp.seqNo,
		            hdr.tcp.ackNo,
		            hdr.tcp.dataOffset,
		            hdr.tcp.res,
		            hdr.tcp.ecn,
		            hdr.tcp.ctrl,
		            hdr.tcp.window,
		            hdr.tcp.urgentPtr,
		            hdr.mss.kind,				//todos os options aq
					hdr.mss.length,				
					hdr.mss.mssValue,
					hdr.sack.kind,
					hdr.sack.lenght,
					hdr.timestamp.kind,
					hdr.timestamp.length,
					hdr.timestamp.tsval_in,
		  			hdr.timestamp.tsval_out,
					hdr.nop_half.nop1,
					hdr.win_scale.kind,
		   			hdr.win_scale.length,
					hdr.win_scale.shift
		        });
			}

			else if(hdr.nop.isValid()){
				hdr.tcp.checksum = tcp_checksum.update({
					hdr.ipv4.src_addr,
					hdr.ipv4.dst_addr,
					hdr.ipv4.total_len,
					hdr.tcp.srcPort,
					hdr.tcp.dstPort,
					hdr.tcp.seqNo,
					hdr.tcp.ackNo,
					hdr.tcp.dataOffset,
					hdr.tcp.res,
					hdr.tcp.ecn,
					hdr.tcp.ctrl,
					hdr.tcp.window,
					hdr.tcp.urgentPtr,
					hdr.nop.nop1,
					hdr.nop.nop2,
					hdr.timestamp.kind,
					hdr.timestamp.length,
					hdr.timestamp.tsval_in,
					hdr.timestamp.tsval_out,
					md.checksum});
		    }

			/*else if(hdr.nop.isValid()){
		        hdr.tcp.checksum = tcp_checksum.update({
		            hdr.ipv4.src_addr,
		            hdr.ipv4.dst_addr,
		            8w0,
		            hdr.ipv4.protocol,
					md.tcpLength,
		            hdr.tcp.srcPort,
		            hdr.tcp.dstPort,
		            hdr.tcp.seqNo,
		            hdr.tcp.ackNo,
		            hdr.tcp.dataOffset,
		            hdr.tcp.res,
		            hdr.tcp.ecn,
		            hdr.tcp.ctrl,
		            hdr.tcp.window,
		            hdr.tcp.urgentPtr,
		            hdr.nop.nop1,
					hdr.nop.nop2,
					hdr.timestamp.kind,
					hdr.timestamp.length,
					hdr.timestamp.tsval_in,
		  			hdr.timestamp.tsval_out
		        });
			}*/

        }



		pkt.emit(hdr);
		//if(md.test == 2){
		//if(ig_intr_dprsr_md.mirror_type == 2){
			//mirror.emit(md.session_ID);
			//mirror.emit<mirror_h>(md.session_ID, {md.pkt_type});	
		//}
		//pkt.emit(hdr);

  }
}


control SwitchIngress(
      inout headers hdr, 
      inout metadata_storage_t md,
      in ingress_intrinsic_metadata_t ig_intr_md,
      in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
      inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
      inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

	Register <bit<16>, bit<1>> (32w1)  recirc;
	



	Register <bit<32>, bit<1>> (32w1)  regSeqNumber;
	Register <bit<32>, bit<1>> (32w1)  regAckNumber;
	Register <bit<32>, bit<1>> (32w1)  regTin;
	Register <bit<32>, bit<1>> (32w1)  regTout;


	RegisterAction<bit<16>, bit<1>, bit<16>>(recirc) recirc_read = {
        void apply(inout bit<16> value, out bit<16> readvalue){
			
			readvalue = value;
			if(value >0){
				value = value - 1;
			}
            
		}
	};

	RegisterAction<bit<16>, bit<1>, bit<16>>(recirc) recirc_write = {
        void apply(inout bit<16> value, out bit<16> readvalue){
			
			value = value + 4;
			//value=md.recirculating;
			readvalue = value;
			
            
		}
	};


	RegisterAction<bit<32>, bit<1>, bit<32>>(regSeqNumber) regSeqNumber_read = {
        void apply(inout bit<32> value, out bit<32> readvalue){			
			readvalue = value;
			value = value + 1448;//funciona?

		}
	};

	RegisterAction<bit<32>, bit<1>, bit<32>>(regAckNumber) regAckNumber_read = {
        void apply(inout bit<32> value, out bit<32> readvalue){			
			readvalue = value;

		}
	};

	RegisterAction<bit<32>, bit<1>, bit<32>>(regSeqNumber) regSeqNumber_write = {
        void apply(inout bit<32> value, out bit<32> readvalue){			
			value = md.seqNo;

		}
	};

	RegisterAction<bit<32>, bit<1>, bit<32>>(regAckNumber) regAckNumber_write = {
        void apply(inout bit<32> value, out bit<32> readvalue){			
			//value = hdr.tcp.ackNo;
			//if(value==0){
				value = md.ackNo;
				//value = hdr.tcp.seqNo;
			//}

		}
	};



	RegisterAction<bit<32>, bit<1>, bit<32>>(regTin) regTin_read = {
        void apply(inout bit<32> value, out bit<32> readvalue){			
			readvalue = value;

		}
	};

	RegisterAction<bit<32>, bit<1>, bit<32>>(regTout) regTout_read = {
        void apply(inout bit<32> value, out bit<32> readvalue){			
			readvalue = value;

		}
	};

	RegisterAction<bit<32>, bit<1>, bit<32>>(regTin) regTin_write = {
        void apply(inout bit<32> value, out bit<32> readvalue){			
			value = md.seqNo;

		}
	};

	RegisterAction<bit<32>, bit<1>, bit<32>>(regTout) regTout_write = {
        void apply(inout bit<32> value, out bit<32> readvalue){			
			//value = hdr.tcp.ackNo;
			value = md.timeAux;

		}
	};





	action drop() {      
		ig_intr_dprsr_md.drop_ctl = 0x1;
		//ig_intr_tm_md.ucast_egress_port = 131;
	}


	action syn(){
		//ig_intr_tm_md.ucast_egress_port = 130;
		//ig_intr_tm_md.ucast_egress_port = 42;
		ig_intr_tm_md.ucast_egress_port = 62;

		hdr.tcp.dataOffset = 10;
		hdr.ipv4.total_len = 60;

		md.tcpLength = 40;

		//hdr.tcp.seqNo = 0x3640b200;
		hdr.tcp.seqNo = 1;
		

		//hdr.tcp.window = 0xfaf0;


		//testando
		//hdr.tcp.window = 1460;
		//hdr.tcp.window = 2920;
		hdr.tcp.window = 5840;

		//hdr.ethernet.dst_addr = 0xac1f6b670670;
		hdr.ethernet.dst_addr = 0x90e2ba27fd3c;

		hdr.ipv4.flags =2;
		
		md.ipv4Check = 1;
		md.tcpCheck = 1;

		//including max segment size configurations
		//hdr.mss.setValid();
		hdr.mss.kind=2;
		hdr.mss.length=4;
		hdr.mss.mssValue=1460;

		//including sack configurations
		//hdr.sack.setValid();
		hdr.sack.kind=4;
		hdr.sack.lenght=2;

		//including timestamp configurations
		//hdr.timestamp.setValid();
		hdr.timestamp.kind=8;
		hdr.timestamp.length=10;
		hdr.timestamp.tsval_in=2875431339;
      	hdr.timestamp.tsval_out=0;
      	//hdr.timestamp.tsecr_msb=0;
      	//hdr.timestamp.tsecr_lsb=0;

		//including a no operation, to allign the packet
		//hdr.nop_half.setValid();
		hdr.nop_half.nop1=1;

		//including the window size configurations
		//hdr.win_scale.setValid();
		hdr.win_scale.kind=3;
   		hdr.win_scale.length=3;
		//hdr.win_scale.shift=14;

		//testando
		//hdr.win_scale.length=3;
		hdr.win_scale.shift=0;


		md.recirculating = 1;	
	}



	action syn_ack(){

		//ig_intr_tm_md.ucast_egress_port = 129;
		//ig_intr_tm_md.ucast_egress_port = 130;//tofino 1 pipe 1
		//ig_intr_tm_md.ucast_egress_port = 42;//tofino 1 pipe 2
		ig_intr_tm_md.ucast_egress_port = 62;//tofino 2 pipe 2

		bit<16> port_aux;
		bit<32> ip_aux;
		bit<48> mac_aux;

		//inverting src and dst port/ip/mac
		ip_aux = hdr.ipv4.src_addr;
		hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
		hdr.ipv4.dst_addr = ip_aux;

		mac_aux = hdr.ethernet.src_addr;
		hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
		hdr.ethernet.dst_addr = mac_aux;

		port_aux = hdr.tcp.srcPort;
		hdr.tcp.srcPort = hdr.tcp.dstPort;
		hdr.tcp.dstPort = port_aux;


		//changinh options configurations, now just with two NOPs and one timestamp
		hdr.mss.setInvalid();
		hdr.sack.setInvalid();
		hdr.nop_half.setInvalid();
		hdr.win_scale.setInvalid();

		hdr.nop.setValid();
		hdr.nop.nop1 = 1;
		hdr.nop.nop2 = 1;
		
		
		md.timeAux = hdr.timestamp.tsval_in;
		
	
		hdr.timestamp.tsval_out = hdr.timestamp.tsval_in;
		hdr.timestamp.tsval_in = 2875431339;
		

		//adjusts in TCP

		bit<32> seq_aux;

		//mudando antes
		md.ackNo = hdr.tcp.seqNo + 1;
		md.seqNo = hdr.tcp.ackNo;


		seq_aux = hdr.tcp.ackNo;
		hdr.tcp.ackNo = hdr.tcp.seqNo + 1;
		hdr.tcp.seqNo = seq_aux;
		hdr.tcp.ctrl = 0x10;
		
		


		//recalculating the packet size
		md.tcpLength = 32;
		hdr.tcp.dataOffset = 8;
		hdr.ipv4.total_len = 52;

		
		//adjust window
		//hdr.tcp.window = 0x0004;
		//hdr.tcp.window = 1460;
		//hdr.tcp.window = 2920;
		hdr.tcp.window = 5840;


		hdr.ipv4.flags = 2;
		hdr.ipv4.identification = 2;
		
		md.recirculating = 2;
		md.recirculating = recirc_write.execute(0);

		
		//recirc_write.execute(0); //tava aq

	}


	action ack(){

		md.ackNo = hdr.tcp.seqNo;
		//md.seqNo = hdr.tcp.ackNo + 1448;
		md.seqNo = hdr.tcp.ackNo;

		md.timeAux = hdr.timestamp.tsval_in;
		//regAckNumber_write.execute(0);

		//to set that I need send more packets
		md.recirculating = 2;
		
		md.recirculating =recirc_write.execute(0); 

	}


	action fin(){
		ig_intr_tm_md.ucast_egress_port = 128;

		//hdr.ethernet.dst_addr = 0xac1f6b670670;
				

		//adjusts in TCP
		hdr.tcp.ackNo = hdr.tcp.seqNo + 1;
		hdr.tcp.seqNo = 1;
		//hdr.tcp.ctrl = 0x18;

		//changinh options configurations, now just with two NOPs and one timestamp
		hdr.mss.setInvalid();
		hdr.sack.setInvalid();
		hdr.nop_half.setInvalid();
		hdr.win_scale.setInvalid();




		hdr.nop.setValid();
		hdr.nop.nop1 = 1;
		hdr.nop.nop2 = 1;

		hdr.timestamp.setValid();
		hdr.timestamp.kind=8;
		hdr.timestamp.length=10;
		hdr.timestamp.tsval_out = hdr.timestamp.tsval_in;
		hdr.timestamp.tsval_in = 2875431339;


		//recalculating the packet size
		md.tcpLength = 32;
		hdr.tcp.dataOffset = 8;
		hdr.ipv4.total_len = 52;


		//adjust window
		hdr.tcp.window = 0x0004;
		hdr.ipv4.flags = 2;
		hdr.ipv4.identification = 3;



	}

	action fin_ack(){


		ig_intr_tm_md.ucast_egress_port = 62;//tofino 2 pipe 2

		bit<16> port_aux;
		bit<32> ip_aux;
		bit<48> mac_aux;

		//inverting src and dst port/ip/mac
		ip_aux = hdr.ipv4.src_addr;
		hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
		hdr.ipv4.dst_addr = ip_aux;

		mac_aux = hdr.ethernet.src_addr;
		hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
		hdr.ethernet.dst_addr = mac_aux;

		port_aux = hdr.tcp.srcPort;
		hdr.tcp.srcPort = hdr.tcp.dstPort;
		hdr.tcp.dstPort = port_aux;


		//changinh options configurations, now just with two NOPs and one timestamp
		//hdr.mss.setInvalid();
		//hdr.sack.setInvalid();
		//hdr.nop_half.setInvalid();
		//hdr.win_scale.setInvalid();

		//hdr.nop.setValid();
		//hdr.nop.nop1 = 1;
		//hdr.nop.nop2 = 1;
		
		
		md.timeAux = hdr.timestamp.tsval_in;
		
	
		hdr.timestamp.tsval_out = hdr.timestamp.tsval_in;
		hdr.timestamp.tsval_in = 2875431339;
		

		//adjusts in TCP

		bit<32> seq_aux;

		//mudando antes
		md.ackNo = hdr.tcp.seqNo + 1;
		md.seqNo = hdr.tcp.ackNo;


		seq_aux = hdr.tcp.ackNo;
		hdr.tcp.ackNo = hdr.tcp.seqNo + 1;
		hdr.tcp.seqNo = seq_aux;
		hdr.tcp.ctrl = 0x10;
		
		


		//recalculating the packet size
		md.tcpLength = 32;
		//hdr.tcp.dataOffset = 8;
		hdr.ipv4.total_len = 52;

		
		//adjust window
		//hdr.tcp.window = 0x0004;
		//hdr.tcp.window = 1460;
		//hdr.tcp.window = 2920;
		hdr.tcp.window = 5840;





	}

	table tcp_type {
  	    key = {
			hdr.tcp.ctrl : exact;
      	}
		actions = {
			syn;
			syn_ack;
			ack;
			fin;
			fin_ack;
			@defaultonly drop;
      	}
		const entries = {
			0x02	: 	syn();
			0x10	: 	ack();
			0x12 	:	syn_ack();
			0x01	:	fin();
			0x11	:	fin_ack();
		}

      	const default_action = drop();
      	size = 5000;
	}




	apply{
		
		

		//
		

		/*
		if(md.realTCP == 3 && ig_intr_md.ingress_port == 68){
			ig_intr_tm_md.ucast_egress_port = 196;
			hdr.timer.app_id = 5;
			//ig_intr_tm_md.ucast_egress_port = 130;
		}
		*/


		//else 
		if (md.realTCP == 3){
			
			//md.tcpLength = 0;
			md.recirculating = 0;
			md.recirculating = recirc_read.execute(0);
			
			//41 - 22/1

			
			//else 
			if(md.recirculating>0 || md.checksumType==22){	//	ig_intr_md.ingress_port == 196	md.recirculating==2

				//if(md.checksumType==22){ // prova de que está certo

				hdr.timer.setInvalid();
				ig_intr_tm_md.ucast_egress_port = 62;
				//ig_intr_tm_md.ucast_egress_port = 130;
				//ig_intr_tm_md.ucast_egress_port = 42;


				//hdr.ethernet.dst_addr = 0xac1f6b670670;
				//hdr.ethernet.dst_addr = 0xac1f6b670670;
				hdr.ethernet.dst_addr = 0x90e2ba27fd3c;				

				//adjusts in TCP
				//hdr.tcp.ackNo = hdr.tcp.seqNo + 1;
				//hdr.tcp.seqNo = 1;
				hdr.tcp.ackNo = regAckNumber_read.execute(0);
				hdr.tcp.seqNo = regSeqNumber_read.execute(0);
				//push ack				
				//hdr.tcp.ctrl = 0x18;
				
				//nsei		
				//hdr.tcp.ctrl = 0x8;

				//ack
				//hdr.tcp.ctrl = 0x10;

				//hdr.nop.setValid();
				hdr.nop.nop1 = 1;
				hdr.nop.nop2 = 1;

				//hdr.timestamp.setValid();
				hdr.timestamp.kind=8;
				hdr.timestamp.length=10;
				hdr.timestamp.tsval_out = regTout_read.execute(0);
				hdr.timestamp.tsval_in = 2875431338;


				//recalculating the packet size
				//md.tcpLength = 1480;
				hdr.tcp.dataOffset = 8;
				//hdr.ipv4.total_len = 1500;
				//hdr.ipv4.total_len = 1500;	
		

				//adjust window
				//hdr.tcp.window = 0x0004;
				//hdr.tcp.window = 1460;
				//hdr.tcp.window = 2920;
				hdr.tcp.window = 5840;
				
				//hdr.ipv4.flags = 2;
				//hdr.ipv4.identification = 3;


				//if(md.checksumType==22){
				/*if(md.recirculating==2){
					//ig_intr_tm_md.ucast_egress_port = 42;
					//ig_intr_tm_md.ucast_egress_port = 134;
					ig_intr_tm_md.ucast_egress_port = 62;
				}
				else{ ig_intr_dprsr_md.drop_ctl = 0x1;}	*/		


			}else{	

				ig_intr_dprsr_md.drop_ctl = 0x1;
				hdr.tcp.setInvalid();
				hdr.nop.setInvalid();
				hdr.timestamp.setInvalid();

			}
		

		}
		//when I receive a real TCP packet and need to save data to awnser
		else if(hdr.tcp.isValid()){
			md.recirculating = 0;
			md.position = 0;
	

	

			//md.ackNo = 0;
			//md.seqNo = 0;
			//md.recirculating = 
			tcp_type.apply();

			
			regSeqNumber_write.execute(0);

			//if(hdr.tcp.ctrl == 0x12){
			regAckNumber_write.execute(0);

			regTout_write.execute(0);

		}
		//When I receive a generated TCP packet and I will check if I need to send it to server or not
		

		
		ig_intr_tm_md.bypass_egress = 1w1;

	}

}


parser EmptyEgressParser(
        packet_in packet,
        out headers hdr,
        out metadata_storage_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

	Checksum() tcp_checksum;


	state start {
		packet.extract(eg_intr_md);
		//pkt.extract(hdr.extra);
		//pkt.extract(hdr.ethernet);
		transition parse_ethernet;
	}


	state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            //ETHERTYPE_ARP:  parse_arp;
            0x800:  parse_ipv4;
            default: accept;
        }
    }


	state parse_ipv4 {
        packet.extract(hdr.ipv4);

		tcp_checksum.subtract({hdr.ipv4.total_len});
		tcp_checksum.subtract({hdr.ipv4.src_addr});
		tcp_checksum.subtract({hdr.ipv4.dst_addr});



        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
			//2: parse_generated_tcp;
            default: accept;
        }
    }


	state parse_tcp {
        packet.extract(hdr.tcp);
      	//md.realTCP = 5;


		tcp_checksum.subtract({hdr.tcp.checksum});
		tcp_checksum.subtract({hdr.tcp.srcPort, hdr.tcp.dstPort});
		tcp_checksum.subtract({hdr.tcp.seqNo, hdr.tcp.ackNo});
		tcp_checksum.subtract({hdr.tcp.dataOffset, hdr.tcp.res, hdr.tcp.ecn, hdr.tcp.ctrl});
		tcp_checksum.subtract({hdr.tcp.window, hdr.tcp.urgentPtr});

		transition select(hdr.tcp.dataOffset) {
            ( 8 ) : parse_nop;
            default : accept;
        }

	
	}


	state parse_nop{
        packet.extract(hdr.nop);

		tcp_checksum.subtract({hdr.nop.nop1, hdr.nop.nop2});
		
		packet.extract(hdr.timestamp);

		tcp_checksum.subtract({hdr.timestamp.kind, hdr.timestamp.length, hdr.timestamp.tsval_in, hdr.timestamp.tsval_out});


		tcp_checksum.subtract_all_and_deposit(eg_md.checksum);


        transition accept;
    }


}


control EmptyEgressDeparser(
        packet_out pkt,
        inout headers hdr,
        in metadata_storage_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {

	Checksum() tcp_checksum;


    apply {
		




		if(hdr.nop.isValid()){
				hdr.tcp.checksum = tcp_checksum.update({
					hdr.ipv4.src_addr,
					hdr.ipv4.dst_addr,
					hdr.ipv4.total_len,
					hdr.tcp.srcPort,
					hdr.tcp.dstPort,
					hdr.tcp.seqNo,
					hdr.tcp.ackNo,
					hdr.tcp.dataOffset,
					hdr.tcp.res,
					hdr.tcp.ecn,
					hdr.tcp.ctrl,
					hdr.tcp.window,
					hdr.tcp.urgentPtr,
					hdr.nop.nop1,
					hdr.nop.nop2,
					hdr.timestamp.kind,
					hdr.timestamp.length,
					hdr.timestamp.tsval_in,
					hdr.timestamp.tsval_out,
					eg_md.checksum});
		    }

		pkt.emit(hdr);
		
	}
}

control EmptyEgress(
        inout headers hdr,
        inout metadata_storage_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply {

		//hdr.ethernet.dst_addr = 0xac1f6b670670;

		//hdr.extra.setInvalid();
		//hdr.timer.setInvalid();
		//hdr.rec.setInvalid();

	}
}



Pipeline(SwitchIngressParser(),
      SwitchIngress(),
      SwitchIngressDeparser(),
      EmptyEgressParser(),
      EmptyEgress(),
      EmptyEgressDeparser()) pipe;

Switch(pipe) main;


