

#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers.p4"

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/

// Ethernet packet field identifying a recirculation header
const ether_type_t ETHERTYPE_REC = 16w0x9966;
// Ethernet type value for IPv4 header
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;

// Used for mirroring logic
typedef bit<8>  pkt_type_t;
typedef bit<3> mirror_type_t;
// Standard packet
const pkt_type_t PKT_TYPE_NORMAL = 1;
// Mirrored packet
const pkt_type_t PKT_TYPE_MIRROR = 2;


/*************************************************************************
 ************************** H E A D E R S  *******************************
**************************************************************************/

// Structure containing the PCAP packet
header data_t{
	bit<32> dataStorage1;
	bit<32> dataStorage2;
	bit<32> dataStorage3;
	bit<32> dataStorage4;
	bit<32> dataStorage5;
	bit<32> dataStorage6;
	bit<32> dataStorage7;
	bit<32> dataStorage8;
	bit<32> dataStorage9;
	bit<32> dataStorage10;
	bit<32> dataStorage11;
	bit<32> dataStorage12;
	bit<32> dataStorage13;
	bit<32> dataStorage14;
	bit<32> dataStorage15;
	bit<32> dataStorage16;
	bit<32> dataStorage17;
	bit<32> dataStorage18;
	bit<32> dataStorage19;
	bit<32> dataStorage20;
	bit<32> dataStorage21;
	bit<32> dataStorage22;
	bit<32> dataStorage23;
	bit<32> dataStorage24;
	bit<32> dataStorage25;
	bit<32> dataStorage26;
	bit<32> dataStorage27;
	bit<32> dataStorage28;
	bit<32> dataStorage29;
	bit<32> dataStorage30;
}

// Header for recirculated packets: initial ingress time, total duration, and position
header rec_h {
	bit<32> initialTime;
	bit<32> totalTime;
	bit<16> position;
}

// Ordered packet headers structure; non-present headers are marked as invalid.
struct headers {
	pktgen_timer_header_t     timer;
	pktgen_port_down_header_t port_down;
	ethernet_h    ethernet;
	rec_h		rec;
	data_t		data;
}
// Metadata structure
struct metadata_storage_t{
	bit<16> position;
	bit<8> recirculating;
	bit<32> timeTotal;
	bit<32> timeDiff;
	bit<1> mirrorS;
	MirrorId_t session_ID;
	pkt_type_t pkt_type;
	mirror_type_t  test; 

}

/*************************************************************************
 ****************** I N G R E S S   P A R S E R S  ***********************
**************************************************************************/

parser SwitchIngressParser(
  packet_in packet, 
  out headers hdr, 
  out metadata_storage_t md, 
  out ingress_intrinsic_metadata_t ig_intr_md) {

// In this initial parser stage, the packet is automatically accepted if the generation header is missing.
	state start {
		packet.extract(ig_intr_md);
		packet.advance(PORT_METADATA_SIZE);

		pktgen_port_down_header_t pktgen_pd_hdr = packet.lookahead<pktgen_port_down_header_t>();
		transition select(pktgen_pd_hdr.app_id) {
			1 : parse_pktgen_timer;
			2 : parse_pktgen_timer;
			3 : parse_pktgen_port_down;
			4 : parse_pktgen_port_down;
			default : parse_ethernet;
		}
	}

// Aqui se extrai o pacote de geração e passa para o parser ethernet
  state parse_pktgen_timer {
      packet.extract(hdr.timer);
      transition parse_ethernet;
  }

// Extracts the Ethernet header. If a recirculation header is present, it transitions to parser_rec; if it is a standard Ethernet packet, an IPv4 header is expected. Otherwise, the packet is rejected.
	state parse_ethernet {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_REC:   parse_rec;
			ETHERTYPE_IPV4: accept;
            default: reject;
        }
    }

	state parse_rec {
		packet.extract(hdr.rec);
		transition accept;
    }

    state parse_pktgen_port_down {
      packet.extract(hdr.port_down);
      transition reject;
  }
}

// Deparser handles packet emission and mirroring. If the metadata mirror type is 2, it emits the mirrored packet according to the Session ID.
control SwitchIngressDeparser(
      packet_out pkt,
      inout headers hdr,
      in metadata_storage_t md,
      in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

	Mirror() mirror;

	apply {

		pkt.emit(hdr);
		if(ig_intr_dprsr_md.mirror_type == 2){
			mirror.emit(md.session_ID);
		}
  }
}


/*************************************************************************
 ****************** I N G R E S S   C O N T R O L  ***********************
**************************************************************************/

control SwitchIngress(
      inout headers hdr, 
      inout metadata_storage_t md,
      in ingress_intrinsic_metadata_t ig_intr_md,
      in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
      inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
      inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {
	

	Register <bit<16>, bit<1>> (32w1)  counter;
	Register <bit<16>, bit<1>> (32w1)  recirc;

	Register <bit<32>, bit<16>> (32w45000)  timer;

	Register <bit<32>, bit<16>> (32w45000)  storage1;

	Register <bit<32>, bit<16>> (32w45000)  storage2;
	Register <bit<32>, bit<16>> (32w45000)  storage3;
	Register <bit<32>, bit<16>> (32w45000)  storage4;
	Register <bit<32>, bit<16>> (32w45000)  storage5;
	Register <bit<32>, bit<16>> (32w45000)  storage6;
	Register <bit<32>, bit<16>> (32w45000)  storage7;
	Register <bit<32>, bit<16>> (32w45000)  storage8;
	Register <bit<32>, bit<16>> (32w45000)  storage9;
	Register <bit<32>, bit<16>> (32w45000)  storage10;
	Register <bit<32>, bit<16>> (32w45000)  storage11;
	Register <bit<32>, bit<16>> (32w45000)  storage12;
	Register <bit<32>, bit<16>> (32w45000)  storage13;
	Register <bit<32>, bit<16>> (32w45000)  storage14;
	Register <bit<32>, bit<16>> (32w45000)  storage15;
	Register <bit<32>, bit<16>> (32w45000)  storage16;
	Register <bit<32>, bit<16>> (32w45000)  storage17;
	Register <bit<32>, bit<16>> (32w45000)  storage18;
	Register <bit<32>, bit<16>> (32w45000)  storage19;
	Register <bit<32>, bit<16>> (32w45000)  storage20;
	Register <bit<32>, bit<16>> (32w45000)  storage21;
	Register <bit<32>, bit<16>> (32w45000)  storage22;
	Register <bit<32>, bit<16>> (32w45000)  storage23;
	Register <bit<32>, bit<16>> (32w45000)  storage24;
	Register <bit<32>, bit<16>> (32w45000)  storage25;
	Register <bit<32>, bit<16>> (32w45000)  storage26;
	Register <bit<32>, bit<16>> (32w45000)  storage27;
	Register <bit<32>, bit<16>> (32w45000)  storage28;
	Register <bit<32>, bit<16>> (32w45000)  storage29;
	Register <bit<32>, bit<16>> (32w45000)  storage30;
	
	RegisterAction<bit<16>, bit<1>, bit<16>>(counter) counter_action = {
        void apply(inout bit<16> value, out bit<16> readvalue){
			readvalue = value;			
			if(value>4864){
				value = 0;
			}else{ value = value+1; }
		}
	};


	RegisterAction<bit<32>, bit<16>, bit<1>>(timer) timer_action = {
        void apply(inout bit<32> value, out bit<1> readvalue){
			readvalue = 1;
		}
	};

	RegisterAction<bit<16>, bit<1>, bit<16>>(recirc) recirc_action = {
        void apply(inout bit<16> value, out bit<16> readvalue){
			readvalue = value;			
			if(value==0){
				value=0;
			}
		}
	};

	RegisterAction<bit<16>, bit<1>, bit<1>>(recirc) recirc_action_yes = {
        void apply(inout bit<16> value, out bit<1> readvalue){
            value = 1;
		}
	};

	RegisterAction<bit<16>, bit<1>, bit<1>>(recirc) recirc_action_no = {
        void apply(inout bit<16> value, out bit<1> readvalue){
			if(hdr.rec.position > 4865){
				value = 1;
				readvalue = 1;

			}
			else{
            	value = 0;
				readvalue = 0;
			}
		}
	};



// Writes the PCAP values to the packet
	RegisterAction<bit<32>, bit<16>, bit<32>>(storage1) storage1_action = {
        void apply(inout bit<32> value, out bit<32> readvalue){
            readvalue = value;
		}
	};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage2) storage2_action = {
		    void apply(inout bit<32> value, out bit<32> readvalue){
		        readvalue = value;
			}
	};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage3) storage3_action = {
		    void apply(inout bit<32> value, out bit<32> readvalue){
		        readvalue = value;
			}
		};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage4) storage4_action = {
		    void apply(inout bit<32> value, out bit<32> readvalue){
		        readvalue = value;
			}
		};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage5) storage5_action = {
		    void apply(inout bit<32> value, out bit<32> readvalue){
		        readvalue = value;
			}
		};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage6) storage6_action = {
		    void apply(inout bit<32> value, out bit<32> readvalue){
		        readvalue = value;
			}
		};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage7) storage7_action = {
		    void apply(inout bit<32> value, out bit<32> readvalue){
		        readvalue = value;
			}
		};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage8) storage8_action = {
		    void apply(inout bit<32> value, out bit<32> readvalue){
		        readvalue = value;
			}
		};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage9) storage9_action = {
		    void apply(inout bit<32> value, out bit<32> readvalue){
		        readvalue = value;
			}
		};


	RegisterAction<bit<32>, bit<16>, bit<32>>(storage10) storage10_action = {
		    void apply(inout bit<32> value, out bit<32> readvalue){
		        readvalue = value;
			}
		};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage11) storage11_action = {
		    void apply(inout bit<32> value, out bit<32> readvalue){
		        readvalue = value;
			}
		};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage12) storage12_action = {
		    void apply(inout bit<32> value, out bit<32> readvalue){
		        readvalue = value;
			}
		};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage13) storage13_action = {
		    void apply(inout bit<32> value, out bit<32> readvalue){
		        readvalue = value;
			}
		};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage14) storage14_action = {
		    void apply(inout bit<32> value, out bit<32> readvalue){
		        readvalue = value;
			}
		};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage15) storage15_action = {
		    void apply(inout bit<32> value, out bit<32> readvalue){
		        readvalue = value;
			}
		};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage16) storage16_action = {
		    void apply(inout bit<32> value, out bit<32> readvalue){
		        readvalue = value;
			}
		};


	RegisterAction<bit<32>, bit<16>, bit<32>>(storage17) storage17_action = {
        void apply(inout bit<32> value, out bit<32> readvalue){
            readvalue = value;
		}
	};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage18) storage18_action = {
		    void apply(inout bit<32> value, out bit<32> readvalue){
		        readvalue = value;
			}
		};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage19) storage19_action = {
		    void apply(inout bit<32> value, out bit<32> readvalue){
		        readvalue = value;
			}
		};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage20) storage20_action = {
		    void apply(inout bit<32> value, out bit<32> readvalue){
		        readvalue = value;
			}
		};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage21) storage21_action = {
				void apply(inout bit<32> value, out bit<32> readvalue){
				    readvalue = value;
				}
			};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage22) storage22_action = {
				void apply(inout bit<32> value, out bit<32> readvalue){
				    readvalue = value;
				}
			};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage23) storage23_action = {
				void apply(inout bit<32> value, out bit<32> readvalue){
				    readvalue = value;
				}
			};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage24) storage24_action = {
				void apply(inout bit<32> value, out bit<32> readvalue){
				    readvalue = value;
				}
			};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage25) storage25_action = {
		void apply(inout bit<32> value, out bit<32> readvalue){
		    readvalue = value;
		}
	};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage26) storage26_action = {
		void apply(inout bit<32> value, out bit<32> readvalue){
		    readvalue = value;
		}
	};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage27) storage27_action = {
		void apply(inout bit<32> value, out bit<32> readvalue){
		    readvalue = value;
		}
	};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage28) storage28_action = {
		void apply(inout bit<32> value, out bit<32> readvalue){
		    readvalue = value;
		}
	};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage29) storage29_action = {
		void apply(inout bit<32> value, out bit<32> readvalue){
		    readvalue = value;
		}
	};

	RegisterAction<bit<32>, bit<16>, bit<32>>(storage30) storage30_action = {
		void apply(inout bit<32> value, out bit<32> readvalue){
		    readvalue = value;
		}
	};



  action drop() {
      ig_intr_dprsr_md.drop_ctl = 0x1;
  }


	// Calculate the difference between the initial timestamp a the current timestamp
    action comp_diff() {
         md.timeDiff = ig_intr_md.ingress_mac_tstamp[31:0] - hdr.rec.initialTime;
    }

	// Action to recirculate the packet
	action recirculate(){
		ig_intr_tm_md.ucast_egress_port = 196;
    }

	// Ation to send the pacekt, forwarding it to other recirculation port to be mirrored and then sent to the output port
	action send(){
		ig_intr_tm_md.ucast_egress_port = 64;

	}

	// Action to get the session ID for the mirror, used to generate the output packet with correct size
	action getSid(MirrorId_t correct){
		md.session_ID = correct;
	}

	table packet_size {
      key = {
          hdr.rec.position : exact;
      }
      actions = {
          getSid;
          @defaultonly drop;
      }
      const default_action = drop();
      size = 5000;
  }



	
	apply {
		ig_intr_dprsr_md.mirror_type = 1;
		md.session_ID = 1;
		md.pkt_type = PKT_TYPE_NORMAL;


		if(hdr.rec.isValid()){

			comp_diff();

			if(timer_action.execute(hdr.rec.position)==1){
				// Packet transmission:
				send();
				ig_intr_dprsr_md.mirror_type = 2;
				md.test = 2;
				md.pkt_type = PKT_TYPE_MIRROR;
				packet_size.apply();
			}else{
				// Packet not ready for transmission;
				ig_intr_dprsr_md.mirror_type = 1;
				md.session_ID = 1;
				recirculate();
			}
		}

		else{
			if(recirc_action.execute(0)==0){
				// Not a packet to recirculate, drop
				drop();
			}else{
				// Its time for the packet recirculated
				// ellimimnation of the Tofino Packet generation header
				hdr.timer.setInvalid();

				md.position = counter_action.execute(0);

				// add the recirculation header to the packet for packet identification and timestamps
				hdr.rec.setValid();
				hdr.rec.position = md.position;
				hdr.rec.initialTime = ig_intr_md.ingress_mac_tstamp[31:0];

				hdr.ethernet.ether_type = ETHERTYPE_REC;

				// add the data header containing the data of the packet defined by the pcap
				hdr.data.setValid();
				hdr.data.dataStorage1 = storage1_action.execute(md.position);
				hdr.data.dataStorage2 = storage2_action.execute(md.position);
				hdr.data.dataStorage3 = storage3_action.execute(md.position);
				hdr.data.dataStorage4 = storage4_action.execute(md.position);
				hdr.data.dataStorage5 = storage5_action.execute(md.position);
				hdr.data.dataStorage6 = storage6_action.execute(md.position);
				hdr.data.dataStorage7 = storage7_action.execute(md.position);
				hdr.data.dataStorage8 = storage8_action.execute(md.position);
				hdr.data.dataStorage9 = storage9_action.execute(md.position);
				hdr.data.dataStorage10 = storage10_action.execute(md.position);
				hdr.data.dataStorage11 = storage11_action.execute(md.position);
				hdr.data.dataStorage12 = storage12_action.execute(md.position);
				hdr.data.dataStorage13 = storage13_action.execute(md.position);
				hdr.data.dataStorage14 = storage14_action.execute(md.position);
				hdr.data.dataStorage15 = storage15_action.execute(md.position);
				hdr.data.dataStorage16 = storage16_action.execute(md.position);
				hdr.data.dataStorage17 = storage17_action.execute(md.position);
				hdr.data.dataStorage18 = storage18_action.execute(md.position);
				hdr.data.dataStorage19 = storage19_action.execute(md.position);
				hdr.data.dataStorage20 = storage20_action.execute(md.position);
				hdr.data.dataStorage21 = storage21_action.execute(md.position);
				hdr.data.dataStorage22 = storage22_action.execute(md.position);
				hdr.data.dataStorage23 = storage23_action.execute(md.position);
				hdr.data.dataStorage24 = storage24_action.execute(md.position);
				hdr.data.dataStorage25 = storage25_action.execute(md.position);
				hdr.data.dataStorage26 = storage26_action.execute(md.position);
				hdr.data.dataStorage27 = storage27_action.execute(md.position);
				hdr.data.dataStorage28 = storage28_action.execute(md.position);
				hdr.data.dataStorage29 = storage29_action.execute(md.position);
				hdr.data.dataStorage30 = storage30_action.execute(md.position);

				// mark to recirculate the packet
				recirculate();
			}
		}
		// All packets, except for the mirrored ones that will actually be sent to the output port, will bypass the Egress pipeline
    	ig_intr_tm_md.bypass_egress = 1w1;
  }
}

/*************************************************************************
 ****************** E G R E S S   P A R S E R S  ***********************
**************************************************************************/

parser SwitchEgressParser(
        packet_in pkt,
        out headers hdr,
        out metadata_storage_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {


	state start {
		// Extraction of headers (to invalidate in Egress Block) and metadata
		pkt.extract(eg_intr_md);
		pkt.extract(hdr.ethernet);
		pkt.extract(hdr.rec);
		transition accept;
	}
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout headers hdr,
        in metadata_storage_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
    apply {
		pkt.emit(hdr);
	}
}


/*************************************************************************
 ****************** E G R E S S   C O N T R O L   ***********************
**************************************************************************/


control SwitchEgress(
        inout headers hdr,
        inout metadata_storage_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply {
		// Remotion of headers added previously
		hdr.rec.setInvalid();
		hdr.ethernet.setInvalid();
	}
}

Pipeline(SwitchIngressParser(),
      SwitchIngress(),
      SwitchIngressDeparser(),
      SwitchEgressParser(),
      SwitchEgress(),
      SwitchEgressDeparser()) pipe;

Switch(pipe) main;

