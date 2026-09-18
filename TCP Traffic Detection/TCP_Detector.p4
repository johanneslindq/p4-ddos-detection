#include <core.p4> // Standard P4 core library
#include <v1model.p4> // BMv2 v1model architecture being targeted


// ----------------------------------------------------------------
// Headers
/* Old Ethernet header syntax:
header_type ethernet_t {
    fields {
        dst_mac : 48;
        src_mac : 48;
        ethertype : 16;
    }
}
*/

header ethernet_t {
    bit<48> dst_mac;
    bit<48> src_mac;
    bit<16> ethertype;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;

    bit<4>  dataOffset;
    bit<3>  reserved;
    bit<1>  ns;

    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;

    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct headers { // Struct containing one instance of all headers note how they change name
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
}

struct metadata { // Empty metadata
}

// ----------------------------------------------------------------
// Parser
parser TCP_Detector_Parser(
    packet_in packet,                            // Input packet
    out headers hdr,                             // Output headers
    inout metadata meta,                         // Inout metadata, metadata is extra information about the packet that only exists on the switch
    inout standard_metadata_t standard_metadata) // Inout standard metadata
{
    state start {                                   // state start is allways the entry state of the parser
        packet.extract(hdr.ethernet);               // Extract the ethernet header from the packet
        transition select(hdr.ethernet.ethertype) { // Transition to the next state based on the ethertype field in the ethernet header
            0x0800: parse_ipv4;                     // If ethertype is 0x0800 (IPv4), transition to parse_ipv4 state
            default: accept;                        // Otherwise, accept the packet and stop parsing
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);                    // Extract the IPv4 header from the packet
        transition select(hdr.ipv4.protocol) {       // Transition to the next state based on the protocol field in the IPv4 header
            6: parse_tcp;                            // If protocol is 6 (TCP), transition to parse_tcp state
            default: accept;                         // Otherwise, accept the packet and stop parsing
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);                     // Extract the TCP header from the packet
        transition accept;                           // Accept the packet and stop parsing
    }

}

// ----------------------------------------------------------------
// Ingress control

control TCP_Detector_Ingress(
    inout headers hdr,                             // Inout headers
    inout metadata meta,                           // Inout metadata
    inout standard_metadata_t standard_metadata)   // Inout standard metadata
{
    
    counter(1, CounterType.packets) tcp_counter;       // counter(1, counter_type.packets) is a built-in function
                                                       // 1 means array containing 1 counter 
                                                       // counter_type.packets means that the counter counts packets, not bytes
    
    apply {
        if (hdr.tcp.isValid()) {                   // checks if the parser has extracted a valid TCP header from the packet
            // TCP packet detected, this is where logic for handling TCP packets goes.
            // For now there will be a counter
            tcp_counter.count(0);                 // Increment the first TCP packet counter by 1

            // Simple two-port forwarding logic based on ingress port
            // We basically forward packets from port 1 to port 2 and vice versa, and drop packets from any other port
            if (standard_metadata.ingress_port == 1) {
                standard_metadata.egress_spec = 2; // Forward to port 2
            } else if (standard_metadata.ingress_port == 2) {
                standard_metadata.egress_spec = 1; // Forward to port 1
            } else {
                mark_to_drop(standard_metadata);   // Drop the packet if it comes from any other
            }
        }
    }
}

// ----------------------------------------------------------------
// Verify checksum control
// From now on any steps in the pipeline basically do nothing, but they are required to be present in the pipeline
control TCP_Detector_VerifyChecksum(
    inout headers hdr,                             
    inout metadata meta)                         
{
    apply { }
}

// ----------------------------------------------------------------
// Egress control
control TCP_Detector_Egress(
    inout headers hdr,                             
    inout metadata meta,                         
    inout standard_metadata_t standard_metadata)
{
    apply { }
}

// ----------------------------------------------------------------
// Compute checksum control
control TCP_Detector_ComputeChecksum(
    inout headers hdr,                             
    inout metadata meta)
{
    apply { }
}

// ----------------------------------------------------------------
// Deparser
control TCP_Detector_Deparser(
    packet_out packet,
    in headers hdr)
{
    apply {
        packet.emit(hdr.ethernet);                 // Emit the ethernet header to the output packet
        packet.emit(hdr.ipv4);                     // Emit the IPv4 header to the output packet
        packet.emit(hdr.tcp);                      // Emit the TCP header to the output packet
    }
}

// ----------------------------------------------------------------
// V1 switch architecture instantiation
// This is like a final decleration for what steps to use in the pipeline

V1Switch(TCP_Detector_Parser(),
         TCP_Detector_VerifyChecksum(),
         TCP_Detector_Ingress(),
         TCP_Detector_Egress(),
         TCP_Detector_ComputeChecksum(),
         TCP_Detector_Deparser()
        ) main;