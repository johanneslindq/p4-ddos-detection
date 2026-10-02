// Configuration
#define COUNT_MIN_BITS 32
#define COUNT_MIN_WIDTH 128

// TODO: Replace with more independent solution.
#define COUNT_MIN_HASHING_ALGORITHM1 HashAlgorithm.crc32
#define COUNT_MIN_HASHING_ALGORITHM2 HashAlgorithm.crc16
#define COUNT_MIN_HASHING_ALGORITHM3 HashAlgorithm.crc32_custom
#define COUNT_MIN_HASHING_ALGORITHM4 HashAlgorithm.crc16_custom

#define COUNT_MIN_HASHING_SEED1 8w1
#define COUNT_MIN_HASHING_SEED2 8w2
#define COUNT_MIN_HASHING_SEED3 8w3
#define COUNT_MIN_HASHING_SEED4 8w4


// Creation
#define count_min_register(register_id, count_min_nr) register<bit<COUNT_MIN_BITS>>(COUNT_MIN_WIDTH) count_min_##count_min_nr##_register_##register_id;

/*
Count-min hashing:
res - variable to put the hash output
use_ipv6 - use ipv6 or ipv4
register_id - count-min row
*/
#define get_count_hash(res, use_ipv6, register_id) \
    if(use_ipv6){ \
        hash(res, COUNT_MIN_HASHING_ALGORITHM##register_id, (bit<COUNT_MIN_BITS>)0, \
            {hdr.ipv6.dstAddr, COUNT_MIN_HASHING_SEED##register_id}, (bit<COUNT_MIN_BITS>)COUNT_MIN_WIDTH-1); \
    } else { \
        hash(res, COUNT_MIN_HASHING_ALGORITHM##register_id, (bit<COUNT_MIN_BITS>)0, \
            {hdr.ipv4.dstAddr, COUNT_MIN_HASHING_SEED##register_id}, (bit<COUNT_MIN_BITS>)COUNT_MIN_WIDTH-1); \
    }

/*
Count-min update register:
register_id - id (1,2,3,...) of row
use_ipv6 - use ipv6 or ipv4
min_var - the variable containing the current minimum, change if the result here is smaller
*/
#define update_count_min(register_id, use_ipv6, min_var, count_min_nr) \
{ \
    bit<COUNT_MIN_BITS> var##register_id; \
    bit<COUNT_MIN_BITS> hash_res##register_id; \
    get_count_hash(hash_res##register_id, use_ipv6, register_id) \
    count_min_##count_min_nr##_register_##register_id.read(var##register_id, (bit<COUNT_MIN_BITS>)hash_res##register_id); \
    var##register_id = var##register_id+1; \
    count_min_##count_min_nr##_register_##register_id.write((bit<COUNT_MIN_BITS>)hash_res##register_id, var##register_id); \
    if(var##register_id < min_var){min_var = var##register_id;} \
} 

/*
Count-min creation
*/
#define create_count_min(count_min_nr) \
    count_min_register(1, count_min_nr) \
    count_min_register(2, count_min_nr) \
    count_min_register(3, count_min_nr) \
    count_min_register(4, count_min_nr)

/*
Count-min main "function":
use_ipv6 - use ipv6 or ipv4
count_result - where to store the minimum value (result)
*/
#define update_all_count_min(count_result, use_ipv6, count_min_nr) \
    update_count_min(1, use_ipv6, count_result, count_min_nr) \
    update_count_min(2, use_ipv6, count_result, count_min_nr) \
    update_count_min(3, use_ipv6, count_result, count_min_nr) \
    update_count_min(4, use_ipv6, count_result, count_min_nr)
