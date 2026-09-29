#define HYPERLOGLOG_NUM_BITS 5
#define HYPERLOGLOG_INDEX_BITS 16
#define HYPERLOGLOG_VALUE_BITS 16
#define HYPERLOGLOG_HASH_BITS (HYPERLOGLOG_INDEX_BITS+HYPERLOGLOG_VALUE_BITS)

#define HYPERLOGLOG_WIDTH (1<<HYPERLOGLOG_INDEX_BITS)


// TODO: Replace with more independent solution (or only count-min?).
#define HYPERLOGLOG_HASHING_ALGORITHM HashAlgorithm.crc32
#define HYPERLOGLOG_SEED 8w123

/*
Create the HLL sketch.
CAN ONLY MAKE ONE!!!!
*/
#define hyperloglog_register register<bit<HYPERLOGLOG_NUM_BITS>>(HYPERLOGLOG_WIDTH) hll_register

/*
HyperLogLog hashing:
res - variable to put the hash output
use_ipv6 - use ipv6 or ipv4
seed - seed for the hash function
*/
#define get_hash(hash_res, use_ipv6, seed) \
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
leading_0_else_if(0) \
leading_0_else_if(1) \
leading_0_else_if(2) \
leading_0_else_if(3) \
leading_0_else_if(4) \
leading_0_else_if(5) \
leading_0_else_if(6) \
leading_0_else_if(7) \
leading_0_else_if(8) \
leading_0_else_if(9) \
leading_0_else_if(10) \
leading_0_else_if(11) \
leading_0_else_if(12) \
leading_0_else_if(13) \
leading_0_else_if(14) \
leading_0_else_if(15) 

/*
Update sketch:
res - where to store output (the count)
use_ipv6 - use ipv6 or not
*/
#define update_hyperloglog(res, use_ipv6) \
bit<HYPERLOGLOG_HASH_BITS> hash_res; \
bit<HYPERLOGLOG_INDEX_BITS> index = hash_res[HYPERLOGLOG_INDEX_BITS-1:0]; \
bit<HYPERLOGLOG_VALUE_BITS> value = hash_res[HYPERLOGLOG_HASH_BITS-1:HYPERLOGLOG_INDEX_BITS]; \
bit<HYPERLOGLOG_NUM_BITS> leading_0s = 0; \
\
get_hash(hash_res, use_ipv6, HYPERLOGLOG_SEED); \
find_leading_0(leading_0s, value) \
hll_register.read(res, index); \
if(leading_0s > res){ \
    res = leading_0s; \
    hll_register.write(index, res); \
}




