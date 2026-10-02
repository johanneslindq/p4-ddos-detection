#include "hyperloglog_long_definitions.p4"
// Basic structure
#define HYPERLOGLOG_NUM_BITS 5 // NOTE: If > 6, change difference calculation.
#define HYPERLOGLOG_INDEX_BITS 10
#define HYPERLOGLOG_VALUE_BITS 16
#define HYPERLOGLOG_HASH_BITS (HYPERLOGLOG_INDEX_BITS+HYPERLOGLOG_VALUE_BITS)

#define HYPERLOGLOG_WIDTH (1<<HYPERLOGLOG_INDEX_BITS)

// TODO: Replace with more independent solution (or only count-min?).
#define HYPERLOGLOG_HASHING_ALGORITHM HashAlgorithm.crc32
#define HYPERLOGLOG_SEED 8w123

//#define HYPERLOGLOG_SMALL_RANGE_CORRECTION_THRESHOLD 2477720000 // 1/(2.5 * 4096 / (0.7213/(1 + 1.079/4096) * 4096**2)) << 21
#define HYPERLOGLOG_SMALL_RANGE_CORRECTION_THRESHOLD 38683753 // 1/(2.5 * 1024 / (0.7213/(1 + 1.079/1024) * 1024**2)) << 17

/*
Create the HLL sketch.
CAN ONLY MAKE ONE!!!!
*/
#define create_hyperloglog register<bit<HYPERLOGLOG_NUM_BITS>>(HYPERLOGLOG_WIDTH) hll_register; 

/*
HyperLogLog hashing:
res - variable to put the hash output
use_ipv6 - use ipv6 or ipv4
seed - seed for the hash function
*/
#define get_hll_hash(hash_res, use_ipv6, seed) \
    if(use_ipv6){ \
        hash(hash_res, HYPERLOGLOG_HASHING_ALGORITHM, (bit<HYPERLOGLOG_HASH_BITS>)0, \
            {hdr.ipv6.srcAddr, seed}, (bit<HYPERLOGLOG_HASH_BITS>)-1); \
    } else { \
        hash(hash_res, HYPERLOGLOG_HASHING_ALGORITHM, (bit<HYPERLOGLOG_HASH_BITS>)0, \
            {hdr.ipv4.srcAddr, seed}, (bit<HYPERLOGLOG_HASH_BITS>)-1); \
    }

/*
Finds if all bits > index are 0:
leading_0s - where to store the output, unchanged if condition is false.
index - the index to check
*/
#define leading_0_else_if(leading_0s, index) else if(value == (bit<HYPERLOGLOG_VALUE_BITS>)value[index:0]){leading_0s=HYPERLOGLOG_VALUE_BITS-index;}

/*
Find leading 0s + 1:
res - variable to put the result, should be 0 initially
value - variable with the input
*/
#define find_leading_0(leading_0s, value) \
if(value == 0){ \
    leading_0s = HYPERLOGLOG_VALUE_BITS+1;  \
} \
leading_0_else_if(leading_0s, 0) \
leading_0_else_if(leading_0s, 1) \
leading_0_else_if(leading_0s, 2) \
leading_0_else_if(leading_0s, 3) \
leading_0_else_if(leading_0s, 4) \
leading_0_else_if(leading_0s, 5) \
leading_0_else_if(leading_0s, 6) \
leading_0_else_if(leading_0s, 7) \
leading_0_else_if(leading_0s, 8) \
leading_0_else_if(leading_0s, 9) \
leading_0_else_if(leading_0s, 10) \
leading_0_else_if(leading_0s, 11) \
leading_0_else_if(leading_0s, 12) \
leading_0_else_if(leading_0s, 13) \
leading_0_else_if(leading_0s, 14) \
leading_0_else_if(leading_0s, 15) 


/*
Update sketch:
res - where to store output (the count)
use_ipv6 - use ipv6 or not
*/
#define update_hyperloglog(use_ipv6) \
{ \
bit<HYPERLOGLOG_HASH_BITS> hash_res; \
bit<HYPERLOGLOG_INDEX_BITS> index; \
bit<HYPERLOGLOG_VALUE_BITS> value; \
bit<HYPERLOGLOG_NUM_BITS> leading_0s = 0; \
bit<HYPERLOGLOG_NUM_BITS> hll_current_val = 0; \
\
get_hll_hash(hash_res, use_ipv6, HYPERLOGLOG_SEED); \
index = hash_res[HYPERLOGLOG_INDEX_BITS-1:0]; \
value = hash_res[HYPERLOGLOG_HASH_BITS-1:HYPERLOGLOG_INDEX_BITS]; \
\
find_leading_0(leading_0s, value) \
\
hll_register.read(hll_current_val, (bit<32>)index); \
if(leading_0s > hll_current_val){ \
    hll_register.write((bit<32>)index, leading_0s); \
} \
} 


#define add_hll_register_value(register_id, hll_sum, number_of_empty_registers) \
hll_register.read(hll_value, register_id); \
if (hll_value == 0) { \
    hll_sum = hll_sum + ((bit<64>)1 << (HYPERLOGLOG_VALUE_BITS + 1)); \
    number_of_empty_registers = number_of_empty_registers + 1; \
} else { \
    hll_sum = hll_sum + ((bit<64>)1 << (HYPERLOGLOG_VALUE_BITS + 1 - hll_value)); \
}


/*
Get the HLL value:
*/
#define get_hll_value(hll_res) \
{ \
bit<HYPERLOGLOG_NUM_BITS> hll_value; \
bit<64> hll_sum = 0; \
bit<HYPERLOGLOG_INDEX_BITS> number_of_empty_registers = 0; \
hll_add_bucket_1024(hll_sum, number_of_empty_registers) \
\
if (hll_sum >= HYPERLOGLOG_SMALL_RANGE_CORRECTION_THRESHOLD) { \
    if (number_of_empty_registers == 0) {hll_res = hll_sum;} \
    hll_hardcoded_else_if_corrections_1024(number_of_empty_registers, hll_res) \
    else { hll_res = 0; } \
} else { \
    hll_res = hll_sum; \
} \
}