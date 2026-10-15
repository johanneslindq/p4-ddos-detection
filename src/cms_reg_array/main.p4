#include <core.p4>
#include <v1model.p4>
#include "../../include/headers.p4"
#include "../../include/countmin.p4"
#include "../../include/tcp_state_tracker_dleft.p4"


#define DIFF_THRESHOLD  500


#define ENABLE_LOGGING

#define log_current_counts(syn_count, ack_count) \
log_msg("-------------SYN COUNT-------------\n");\
log_msg("The current SYN count for this destination is: {}\n", {syn_count}); \
log_msg("-------------ACK COUNT-------------\n");\
log_msg("The current ACK count for this destination is: {}\n", {ack_count}); \



parser SYNParser(packet_in packet, out headers hdr, inout metadata_state meta, inout standard_metadata_t standard_metadata) {
    
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


control SYNControllerIngress(inout headers hdr, inout metadata_state meta, inout standard_metadata_t standard_metadata) {
    // Create the sketches
    create_count_min(1) 
    create_count_min(3)

    create_state_tracker // 2-bit X length register array.
    

    action drop_packet() {
        mark_to_drop(standard_metadata);
    }


    apply {
        bool any_ip_valid = (hdr.ipv6.isValid() || hdr.ipv4.isValid());

        if (hdr.tcp.isValid() && any_ip_valid) {
            bit<32> dl_fx;
            bit<32> dl_idx1;
            bit<32> dl_idx2;
            bit<STATE_FINGERPRINT_BITS> dl_rem1;
            bit<STATE_FINGERPRINT_BITS> dl_rem2;

            // Extract packet type
            if(hdr.tcp.syn == 1 && hdr.tcp.ack == 1) meta.packet_type = 2;
            else if(hdr.tcp.syn == 1) meta.packet_type = 1;
            else if(hdr.tcp.ack == 1) meta.packet_type = 3;
            else meta.packet_type = 0;

            meta.server_source = (standard_metadata.ingress_port == 1); // server is source if port == 1

            // Populate server/client ip & port
            if (hdr.ipv6.isValid()) {
                if (meta.server_source) {
                    meta.serverIP = hdr.ipv6.srcAddr;
                    meta.serverPort = hdr.tcp.srcPort;
                    meta.clientIP = hdr.ipv6.dstAddr;
                    meta.clientPort = hdr.tcp.dstPort;

                } else {
                    meta.serverIP = hdr.ipv6.dstAddr;
                    meta.serverPort = hdr.tcp.dstPort;
                    meta.clientIP = hdr.ipv6.srcAddr;
                    meta.clientPort = hdr.tcp.srcPort;

                }
            } else if (hdr.ipv4.isValid()) {
                if (meta.server_source) {
                    meta.serverIP = (bit<96>)0 ++ hdr.ipv4.srcAddr;
                    meta.serverPort = hdr.tcp.srcPort;
                    meta.clientIP = (bit<96>)0 ++ hdr.ipv4.dstAddr;
                    meta.clientPort = hdr.tcp.dstPort;
                } else {
                    meta.serverIP = (bit<96>)0 ++ hdr.ipv4.dstAddr;
                    meta.serverPort = hdr.tcp.dstPort;
                    meta.clientIP = (bit<96>)0 ++ hdr.ipv4.srcAddr;
                    meta.clientPort = hdr.tcp.srcPort;

                }
            }

            get_state_tracker_hash(dl_fx)
            get_state_tracker_locations(dl_fx, dl_idx1, dl_rem1, dl_idx2, dl_rem2)
            read_state_tracker(meta.state_bits, dl_idx1, dl_rem1, dl_idx2, dl_rem2)

            if(meta.packet_type == 2 && meta.state_bits == 1) {
                update_state_tracker(2w2, dl_idx1, dl_rem1, dl_idx2, dl_rem2)
            }

            if(meta.packet_type == 1 || meta.packet_type == 3){
                count_min_bits_t ack_count = (count_min_bits_t)(-1);
                count_min_bits_t syn_count = (count_min_bits_t)(-1);

                count_min_bits_t hash_res1;
                count_min_bits_t hash_res2;
                count_min_bits_t hash_res3;
                count_min_bits_t hash_res4;

                count_min_bits_t syn_var1;
                count_min_bits_t syn_var2;
                count_min_bits_t syn_var3;
                count_min_bits_t syn_var4;
               
                count_min_bits_t ack_var1;
                count_min_bits_t ack_var2;
                count_min_bits_t ack_var3;
                count_min_bits_t ack_var4;

                get_count_hash_agnostic(hash_res1, 1) // Shared hash
                get_count_hash_agnostic(hash_res2, 2) // Shared hash
                get_count_hash_agnostic(hash_res3, 3) // Shared hash
                get_count_hash_agnostic(hash_res4, 4) // Shared hash

                if(meta.packet_type == 1){
                    read_ack_cms
                    if(meta.state_bits == 0 || meta.state_bits == 3){
                        update_state_tracker(2w1, dl_idx1, dl_rem1, dl_idx2, dl_rem2)
                        update_syn_cms
                    } else{
                        read_syn_cms
                    }
                } else{
                    read_syn_cms
                    if(meta.state_bits == 2){
                        update_state_tracker(2w3, dl_idx1, dl_rem1, dl_idx2, dl_rem2) 
                        update_ack_cms
                    } else{
                        read_ack_cms
                    }
                }
                
                #ifdef ENABLE_LOGGING
                log_current_counts(syn_count, ack_count)
                #endif

                count_min_diff_bits_t diff = (count_min_diff_bits_t)(bit<33>)syn_count - (count_min_diff_bits_t)(bit<33>)ack_count;
                if(diff > DIFF_THRESHOLD){
                    drop_packet();
                }
            }
        } 
    }
}

// Från Githubben:

control MyVerifyChecksum(inout headers hdr, inout metadata_state meta) {
    apply {  }
}

control MyEgress(inout headers hdr,
                 inout metadata_state meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

control MyComputeChecksum(inout headers hdr, inout metadata_state meta) {
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
