struct metadata_state {
    bit<2> state_bits;
    bit<2> packet_type;

    bool use_ipv6;
    bool server_source;

    bit<128> serverIP;
    bit<128> clientIP;
    bit<16> serverPort;
    bit<16> clientPort;
}

#define STATE_ELEMENT_BIT_SIZE 2
#define STATE_NUMBER_ELEMENTS 32w1048576 // 2^20
#define STATE_NUMBER_ELEMENTS_LIMIT 32w1048575 // 2^20 -1

#define STATE_HASHING_ALGORITHM HashAlgorithm.crc32

#define create_state_tracker \
register<bit<STATE_ELEMENT_BIT_SIZE>>(STATE_NUMBER_ELEMENTS) state_tracker;

#define get_state_tracker_hash(state_hash_res) \
hash(state_hash_res, STATE_HASHING_ALGORITHM, (bit<32>)0, \
            {meta.serverIP,meta.serverPort,meta.clientIP,meta.clientPort, 8w120}, STATE_NUMBER_ELEMENTS_LIMIT); \

#define update_state_tracker(new_value, state_hash_res) \
state_tracker.write(state_hash_res, new_value);

#define update_state_tracker_new_hash(new_value) \
bit<32> state_hash_res; \
get_state_tracker_hash(state_hash_res) \
state_tracker.write(state_hash_res, new_value);

#define read_state_tracker(output, state_hash_res) \
state_tracker.read(output, state_hash_res); \

#define read_state_tracker_new_hash(output) \
bit<32> state_hash_res; \
get_state_tracker_hash(state_hash_res) \
state_tracker.read(output, state_hash_res);


#define read_syn_cms \
count_min_##1##_register_##1.read(syn_var1, (bit<COUNT_MIN_BITS>)hash_res1); \
if(syn_var1 < syn_count){syn_count = syn_var1;} \
count_min_##1##_register_##2.read(syn_var2, (bit<COUNT_MIN_BITS>)hash_res2); \
if(syn_var2 < syn_count){syn_count = syn_var2;} \
count_min_##1##_register_##3.read(syn_var3, (bit<COUNT_MIN_BITS>)hash_res3); \
if(syn_var3 < syn_count){syn_count = syn_var3;} \
count_min_##1##_register_##4.read(syn_var4, (bit<COUNT_MIN_BITS>)hash_res4); \
if(syn_var4 < syn_count){syn_count = syn_var4;} 

#define read_ack_cms \
count_min_##3##_register_##1.read(ack_var1, (bit<COUNT_MIN_BITS>)hash_res1); \
if(ack_var1 < ack_count){ack_count = ack_var1;} \
count_min_##3##_register_##2.read(ack_var2, (bit<COUNT_MIN_BITS>)hash_res2); \
if(ack_var2 < ack_count){ack_count = ack_var2;} \
count_min_##3##_register_##3.read(ack_var3, (bit<COUNT_MIN_BITS>)hash_res3); \
if(ack_var3 < ack_count){ack_count = ack_var3;} \
count_min_##3##_register_##4.read(ack_var4, (bit<COUNT_MIN_BITS>)hash_res4); \
if(ack_var4 < ack_count){ack_count = ack_var4;} 

#define update_syn_cms \
update_count_min_existing_hash(1, syn_count, 1, hash_res1) \
update_count_min_existing_hash(2, syn_count, 1, hash_res2) \
update_count_min_existing_hash(3, syn_count, 1, hash_res3) \
update_count_min_existing_hash(4, syn_count, 1, hash_res4) 

#define update_ack_cms \
update_count_min_existing_hash(1, ack_count, 3, hash_res1) \
update_count_min_existing_hash(2, ack_count, 3, hash_res2) \
update_count_min_existing_hash(3, ack_count, 3, hash_res3) \
update_count_min_existing_hash(4, ack_count, 3, hash_res4) 