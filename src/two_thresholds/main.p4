#include <core.p4>
#include <v1model.p4>
#include "../../include/headers.p4"
#include "../../include/countmin.p4"
#include "../../include/p4loglog.p4"

#define UNIQUE_SOURCES_THRESHOLD  500
#define SYN_PER_DESTINATION_THRESHOLD  500

#define ENABLE_LOGGING

#define log_current_counts(count_min_value, pll_res) \
log_msg("-------------COUNT-MIN COUNT-------------\n");\
log_msg("The current SYN count for this destination is: {}\n", {count_min_value}); \
log_msg("-------------PLL COUNT-------------\n");\
log_msg("The current source count: {}\n", {pll_res});

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
    action drop_packet() {
        mark_to_drop(standard_metadata);
    }


    // Create the sketches
    create_count_min(0)
    create_p4loglog

    apply {
        bool any_ip_valid = (hdr.ipv6.isValid() || hdr.ipv4.isValid());

        if (hdr.tcp.isValid() && any_ip_valid && hdr.tcp.syn == 1 && hdr.tcp.ack == 0) {

            count_min_bits_t count_min_value = (count_min_bits_t)(-1); // variable will be filled with current count
            update_all_count_min(count_min_value, hdr.ipv6.isValid(), 0)

            update_p4loglog(meta.pll_res)
            

            #ifdef ENABLE_LOGGING
            log_current_counts(count_min_value, meta.pll_res)
            #endif

            if(count_min_value > SYN_PER_DESTINATION_THRESHOLD && meta.pll_res > UNIQUE_SOURCES_THRESHOLD){
                #ifdef ENABLE_LOGGING
                log_msg("DDOS thresholds passed.");
                #endif
                drop_packet();
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
        packet.emit(hdr.ipv6);
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