// Basic structure
#define P4LOGLOG_NUM_BITS 5 // NOTE: If > 6, change difference calculation.
#define P4LOGLOG_INDEX_BITS 10
#define P4LOGLOG_VALUE_BITS 22
#define P4LOGLOG_HASH_BITS (P4LOGLOG_INDEX_BITS+P4LOGLOG_VALUE_BITS)
#define P4LOGLOG_WIDTH (1<<P4LOGLOG_INDEX_BITS)
#define P4LOGLOG_HASHING_ALGORITHM HashAlgorithm.crc32
#define P4LOGLOG_SEED 8w123

#define P4LOGLOG_ALPHA 415744 //0.397*2^10*m

#define create_p4loglog \
register<bit<P4LOGLOG_NUM_BITS>>(P4LOGLOG_WIDTH) pll_register; \
register<bit<32>>(1) p4loglog_sum_reg;

/*
P4LogLog hashing:
res - variable to put the hash output
use_ipv6 - use ipv6 or ipv4
seed - seed for the hash function
*/
#define get_pll_hash(hash_res, use_ipv6, seed) \
    if(use_ipv6){ \
        hash(hash_res, P4LOGLOG_HASHING_ALGORITHM, (bit<P4LOGLOG_HASH_BITS>)0, \
            {hdr.ipv6.srcAddr, seed}, (bit<P4LOGLOG_HASH_BITS>)-1); \
    } else { \
        hash(hash_res, P4LOGLOG_HASHING_ALGORITHM, (bit<P4LOGLOG_HASH_BITS>)0, \
            {hdr.ipv4.srcAddr, seed}, (bit<P4LOGLOG_HASH_BITS>)-1); \
    }

#define p4loglog_cardinality(pll_sum, pll_count) \
pll_sum = pll_sum >> P4LOGLOG_INDEX_BITS; \
pll_count = ((bit<32>)1 << (bit<8>)pll_sum); \
pll_count = (P4LOGLOG_ALPHA * pll_count ) >> 10; 

#define read_p4loglog(pll_count) \
bit<32> pll_sum; \
p4loglog_sum_reg.read(pll_sum, (bit<32>)0); \
p4loglog_cardinality(pll_sum, pll_count)

#define update_p4loglog(pll_count) \
{ \
    bit<P4LOGLOG_HASH_BITS> hash_res; \
    bit<P4LOGLOG_INDEX_BITS> index; \
    bit<P4LOGLOG_VALUE_BITS> value; \
    bit<32> x; \
    bit<32> bit_count; \
    bit<P4LOGLOG_NUM_BITS> first_one_pos; \
    bit<P4LOGLOG_NUM_BITS> current_max = 0; \
    \
    get_pll_hash(hash_res, hdr.ipv6.isValid(), P4LOGLOG_SEED); \
    index = hash_res[P4LOGLOG_INDEX_BITS-1 : 0]; \
    value = hash_res[P4LOGLOG_HASH_BITS-1 : P4LOGLOG_INDEX_BITS]; \
    \
    x = (bit<32>)value; \
    \
    x = x | (x << 1); \
    x = x | (x << 2); \
    x = x | (x << 4); \
    x = x | (x << 8); \
    x = x | (x << 16); \
    \
    x = x - ((x >> 1) & 0x55555555); \
    x = (x & 0x33333333) + ((x >> 2) & 0x33333333); \
    x = (x + (x >> 4)) & 0x0F0F0F0F; \
    x = x + (x >> 8); \
    x = x + (x >> 16); \
    bit_count = x & 0x0000003F; \
    \
    first_one_pos = (bit<P4LOGLOG_NUM_BITS>)((bit<32>)(P4LOGLOG_VALUE_BITS + 1) - bit_count); \
    \
    pll_register.read(current_max, (bit<32>)index); \
    if (first_one_pos > current_max) { \
        bit<32> current_sum; \
        pll_register.write((bit<32>)index, first_one_pos); \
        p4loglog_sum_reg.read(current_sum, (bit<32>)0); \
        current_sum = current_sum + (bit<32>)(first_one_pos - current_max); \
        p4loglog_sum_reg.write((bit<32>)0, current_sum); \
        p4loglog_cardinality(current_sum, pll_count) \
    } else {\
        read_p4loglog(pll_count) \
    } \
}

