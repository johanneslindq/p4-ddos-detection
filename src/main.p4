#include <core.p4>
#include <v1model.p4>
#include "../include/headers-65536.p4"
#include "../include/countmin.p4"

parser SYNParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    
    state start {
        packet.extract(hdr.ethernet);
        
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4; 
            TYPE_IPV6: parse_ipv6;
            default: accept; 
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}


control SYNControllerIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    create_count_min // Create the registers

    action drop_packet() {
        mark_to_drop(standard_metadata);
    }

    apply {
        if (hdr.tcp.isValid() && hdr.tcp.syn == 1 && hdr.tcp.ack == 0) {
            bit<COUNT_MIN_BITS> count_min_value = (bit<COUNT_MIN_BITS>)-1; // variable will be filled with current count
            
            // ipv6 not implemented yet
            if(hdr.ipv4.isValid()){
                update_all_count_min(count_min_value, !hdr.ipv4.isValid());  
            } else {
                drop_packet();
            }

            log_msg("The current count is: {}", {count_min_value});
            if(count_min_value > 10000){
                drop_packet();
                exit;
            }
        } 
    }
}

// Från Githubben:
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

V1Switch(
SYNParser(),
MyVerifyChecksum(),
SYNControllerIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;