#include <core.p4>
#include <v1model.p4>
#include "../include/headers.p4"
#include "../include/countmin.p4"
#include "../include/hyperloglog.p4"

#define UNIQUE_SOURCES_THRESHOLD  500
#define SYN_PER_DESTINATION_THRESHOLD  500

#define ENABLE_LOGGING
#define log_current_counts(count_min_value, hyperloglog_value) \
log_msg("-------------COUNT-MIN COUNT-------------");\
log_msg("The current SYN count for this destination is: {}", {count_min_value});\
log_msg("-------------HYPERLOGLOG COUNT-------------");\
log_msg("The current source count is: {}", {hyperloglog_value});

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
    // Create the sketches
    create_count_min 
    hyperloglog_register 

    // Passive benchmark instrumentation; BMv2 initializes this to zero.
    // Keep cumulative across detector/sketch resets (wraps at 2^32).
    register<bit<32>>(1) detection_count;

    action mark_attack_detected() {
        bit<32> value;
        detection_count.read(value, 0);
        value = value + 1;
        detection_count.write(0, value);
    }

    action drop_packet() {
        mark_to_drop(standard_metadata);
    }

    apply {
        bool use_ipv6 = (hdr.ipv6.isValid() && !hdr.ipv4.isValid());

        if (hdr.tcp.isValid() && hdr.tcp.syn == 1 && hdr.tcp.ack == 0) {
            bit<COUNT_MIN_BITS> count_min_value = (bit<COUNT_MIN_BITS>)-1; // variable will be filled with current count
            bit<HYPERLOGLOG_HASH_BITS> hyperloglog_value;

            // ipv6 not implemented yet
            if(hdr.ipv4.isValid()){
                update_all_count_min(count_min_value, use_ipv6)
                update_hyperloglog(use_ipv6)
                // TODO: Get HLL value.
            } else {
                drop_packet();
            }

            #ifdef ENABLE_LOGGING
            log_current_counts(count_min_value, hyperloglog_value)
            #endif

            if(hyperloglog_value > UNIQUE_SOURCES_THRESHOLD && count_min_value > SYN_PER_DESTINATION_THRESHOLD){
                mark_attack_detected(); // This is to later let the benchmark know that an attack was detected, so it can log it
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
