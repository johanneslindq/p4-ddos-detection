// Configuration
#define COUNT_MIN_BITS 32
#define COUNT_MIN_WIDTH 128

// TODO: Replace with more independent solution.
#define COUNT_MIN_HASHING_ALGORITHM HashAlgorithm.crc32

// Creation
#define count_min_register(register_id) register<bit<COUNT_MIN_BITS>>(COUNT_MIN_WIDTH) count_min_register_##register_id;

/*
Count-min hashing:
res - variable to put the hash output
use_ipv6 - use ipv6 or ipv4
seed - seed for the hash function, should be different for all
*/
#define get_count_min_hash(res, use_ipv6, seed) \
    if(use_ipv6){ \
        hash(res, COUNT_MIN_HASHING_ALGORITHM, (bit<COUNT_MIN_BITS>)0, \
            {hdr.ipv6.dstAddr, seed}, (bit<COUNT_MIN_BITS>)COUNT_MIN_WIDTH-1); \
    } else { \
        hash(res, COUNT_MIN_HASHING_ALGORITHM, (bit<COUNT_MIN_BITS>)0, \
            {hdr.ipv4.dstAddr, seed}, (bit<COUNT_MIN_BITS>)COUNT_MIN_WIDTH-1); \
    }

/*
Count-min update register:
register_id - id (1,2,3,...) of row
use_ipv6 - use ipv6 or ipv4
min_var - the variable containing the current minimum, change if the result here is smaller
*/
#define update_count_min(register_id, use_ipv6, min_var) \
    bit<COUNT_MIN_BITS> var##register_id; \
    bit<COUNT_MIN_BITS> hash_res##register_id; \
    get_hash(hash_res##register_id, use_ipv6, 8w##register_id) \
    count_min_register_##register_id.read(var##register_id, (bit<COUNT_MIN_BITS>)hash_res##register_id); \
    var##register_id = var##register_id+1; \
    count_min_register_##register_id.write((bit<COUNT_MIN_BITS>)hash_res##register_id, var##register_id); \
    if(var##register_id < min_var){min_var = var##register_id;}

/*
Count-min creation
*/
#define create_count_min \
    count_min_register(1) \
    count_min_register(2) \
    count_min_register(3) \
    count_min_register(4)

/*
Count-min main "function":
use_ipv6 - use ipv6 or ipv4
count_result - where to store the minimum value (result)
*/
#define update_all_count_min(count_result, use_ipv6) \
    update_count_min(1, use_ipv6, count_result) \
    update_count_min(2, use_ipv6, count_result) \
    update_count_min(3, use_ipv6, count_result) \
    update_count_min(4, use_ipv6, count_result)
