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

/*
 * d-left hashing state tracker (d = 2), following Bonomi et al.
 * ("An Improved Construction for Counting Bloom Filters" / "Beyond Bloom Filters"):
 *
 *   1. One strong hash H(flow) gives a "true fingerprint" fx of
 *      STATE_BUCKET_BITS + STATE_FINGERPRINT_BITS = 31 bits.
 *   2. Two permutations P1, P2 (fx * odd_constant mod 2^31, a bijection) give
 *      one (bucket, remainder) pair per subtable:
 *          high 17 bits -> bucket index, low 14 bits -> remainder (stored)
 *   3. Each subtable has STATE_NUMBER_BUCKETS buckets of 4 cells.
 *      A cell = {remainder (14 bits), state (2 bits)}; remainder 0 = empty cell
 *      (a remainder that would be 0 is mapped to 1).
 *   4. Insert: if the remainder is already in one of the 2 buckets, only the
 *      state is changed; otherwise it goes in the least loaded bucket, ties
 *      broken to the left (subtable 1). If both buckets are full, the entry
 *      is dropped (overflow).
 *   5. Lookup: state of the matching remainder, or 0 if none is found.
 *
 * Total cells = 2 subtables * 2^17 buckets * 4 cells = 2^20 (same as before).
 * Keep STATE_BUCKET_BITS / STATE_NUMBER_BUCKETS / STATE_FX_* consistent.
 */

#define STATE_ELEMENT_BIT_SIZE 2
#define STATE_BUCKET_BITS 17
#define STATE_FINGERPRINT_BITS 14
#define STATE_CELL_BITS 16
#define STATE_NUMBER_BUCKETS 32w131072 // 2^17 buckets per subtable
#define STATE_FX_RANGE 32w2147483648   // 2^31 = 2^(BUCKET_BITS + FINGERPRINT_BITS)
#define STATE_FX_MASK 32w0x7FFFFFFF
#define STATE_PERM_MULT_1 32w0x9E3779B1 // odd -> P1 is a permutation mod 2^31
#define STATE_PERM_MULT_2 32w0x85EBCA6B // odd -> P2 is a permutation mod 2^31
#define STATE_HASHING_ALGORITHM HashAlgorithm.crc32

#define STATE_CELL_FP_HIGH 15
#define STATE_CELL_FP_LOW 2
#define STATE_CELL_STATE_HIGH 1
#define STATE_CELL_FP(c) c[STATE_CELL_FP_HIGH:STATE_CELL_FP_LOW]
#define STATE_CELL_VALUE(c) c[STATE_CELL_STATE_HIGH:0]

#define create_state_tracker \
register<bit<STATE_CELL_BITS>>(STATE_NUMBER_BUCKETS) state_tracker_1_1; \
register<bit<STATE_CELL_BITS>>(STATE_NUMBER_BUCKETS) state_tracker_1_2; \
register<bit<STATE_CELL_BITS>>(STATE_NUMBER_BUCKETS) state_tracker_1_3; \
register<bit<STATE_CELL_BITS>>(STATE_NUMBER_BUCKETS) state_tracker_1_4; \
register<bit<STATE_CELL_BITS>>(STATE_NUMBER_BUCKETS) state_tracker_2_1; \
register<bit<STATE_CELL_BITS>>(STATE_NUMBER_BUCKETS) state_tracker_2_2; \
register<bit<STATE_CELL_BITS>>(STATE_NUMBER_BUCKETS) state_tracker_2_3; \
register<bit<STATE_CELL_BITS>>(STATE_NUMBER_BUCKETS) state_tracker_2_4;

/* true fingerprint of the flow (first phase): state_fx must be a declared bit<32> */
#define get_state_tracker_hash(state_fx) \
hash(state_fx, STATE_HASHING_ALGORITHM, (bit<32>)0, \
            {meta.serverIP,meta.serverPort,meta.clientIP,meta.clientPort, 8w120}, STATE_FX_RANGE);

/* second phase: permutations -> (bucket, remainder) for subtables 1 and 2.
   idx are declared bit<32>, rem are declared bit<STATE_FINGERPRINT_BITS> */
#define get_state_tracker_locations(state_fx, state_idx1, state_rem1, state_idx2, state_rem2) \
state_idx1 = ((state_fx * STATE_PERM_MULT_1) & STATE_FX_MASK) >> STATE_FINGERPRINT_BITS; \
state_rem1 = (bit<STATE_FINGERPRINT_BITS>)(state_fx * STATE_PERM_MULT_1); \
if (state_rem1 == 0) { state_rem1 = 1; } \
state_idx2 = ((state_fx * STATE_PERM_MULT_2) & STATE_FX_MASK) >> STATE_FINGERPRINT_BITS; \
state_rem2 = (bit<STATE_FINGERPRINT_BITS>)(state_fx * STATE_PERM_MULT_2); \
if (state_rem2 == 0) { state_rem2 = 1; }

#define declare_state_tracker_cells \
bit<STATE_CELL_BITS> state_cell_1_1; \
bit<STATE_CELL_BITS> state_cell_1_2; \
bit<STATE_CELL_BITS> state_cell_1_3; \
bit<STATE_CELL_BITS> state_cell_1_4; \
bit<STATE_CELL_BITS> state_cell_2_1; \
bit<STATE_CELL_BITS> state_cell_2_2; \
bit<STATE_CELL_BITS> state_cell_2_3; \
bit<STATE_CELL_BITS> state_cell_2_4;

#define load_state_tracker_cells(state_idx1, state_idx2) \
state_tracker_1_1.read(state_cell_1_1, state_idx1); \
state_tracker_1_2.read(state_cell_1_2, state_idx1); \
state_tracker_1_3.read(state_cell_1_3, state_idx1); \
state_tracker_1_4.read(state_cell_1_4, state_idx1); \
state_tracker_2_1.read(state_cell_2_1, state_idx2); \
state_tracker_2_2.read(state_cell_2_2, state_idx2); \
state_tracker_2_3.read(state_cell_2_3, state_idx2); \
state_tracker_2_4.read(state_cell_2_4, state_idx2);

/* insert the flow, or change its state if it is already stored */
#define update_state_tracker(new_value, state_idx1, state_rem1, state_idx2, state_rem2) \
{ \
    declare_state_tracker_cells \
    bool state_found = false; \
    bit<8> state_load1 = 0; \
    bit<8> state_load2 = 0; \
    load_state_tracker_cells(state_idx1, state_idx2) \
    if (STATE_CELL_FP(state_cell_1_1) == state_rem1) { \
        state_tracker_1_1.write(state_idx1, state_rem1 ++ new_value); state_found = true; \
    } else if (STATE_CELL_FP(state_cell_1_2) == state_rem1) { \
        state_tracker_1_2.write(state_idx1, state_rem1 ++ new_value); state_found = true; \
    } else if (STATE_CELL_FP(state_cell_1_3) == state_rem1) { \
        state_tracker_1_3.write(state_idx1, state_rem1 ++ new_value); state_found = true; \
    } else if (STATE_CELL_FP(state_cell_1_4) == state_rem1) { \
        state_tracker_1_4.write(state_idx1, state_rem1 ++ new_value); state_found = true; \
    } else if (STATE_CELL_FP(state_cell_2_1) == state_rem2) { \
        state_tracker_2_1.write(state_idx2, state_rem2 ++ new_value); state_found = true; \
    } else if (STATE_CELL_FP(state_cell_2_2) == state_rem2) { \
        state_tracker_2_2.write(state_idx2, state_rem2 ++ new_value); state_found = true; \
    } else if (STATE_CELL_FP(state_cell_2_3) == state_rem2) { \
        state_tracker_2_3.write(state_idx2, state_rem2 ++ new_value); state_found = true; \
    } else if (STATE_CELL_FP(state_cell_2_4) == state_rem2) { \
        state_tracker_2_4.write(state_idx2, state_rem2 ++ new_value); state_found = true; \
    } \
    if (!state_found) { \
        if (STATE_CELL_FP(state_cell_1_1) != 0) { state_load1 = state_load1 + 1; } \
        if (STATE_CELL_FP(state_cell_1_2) != 0) { state_load1 = state_load1 + 1; } \
        if (STATE_CELL_FP(state_cell_1_3) != 0) { state_load1 = state_load1 + 1; } \
        if (STATE_CELL_FP(state_cell_1_4) != 0) { state_load1 = state_load1 + 1; } \
        if (STATE_CELL_FP(state_cell_2_1) != 0) { state_load2 = state_load2 + 1; } \
        if (STATE_CELL_FP(state_cell_2_2) != 0) { state_load2 = state_load2 + 1; } \
        if (STATE_CELL_FP(state_cell_2_3) != 0) { state_load2 = state_load2 + 1; } \
        if (STATE_CELL_FP(state_cell_2_4) != 0) { state_load2 = state_load2 + 1; } \
        if (state_load1 <= state_load2) { \
            if (STATE_CELL_FP(state_cell_1_1) == 0) { \
                state_tracker_1_1.write(state_idx1, state_rem1 ++ new_value); \
            } else if (STATE_CELL_FP(state_cell_1_2) == 0) { \
                state_tracker_1_2.write(state_idx1, state_rem1 ++ new_value); \
            } else if (STATE_CELL_FP(state_cell_1_3) == 0) { \
                state_tracker_1_3.write(state_idx1, state_rem1 ++ new_value); \
            } else if (STATE_CELL_FP(state_cell_1_4) == 0) { \
                state_tracker_1_4.write(state_idx1, state_rem1 ++ new_value); \
            } \
        } else { \
            if (STATE_CELL_FP(state_cell_2_1) == 0) { \
                state_tracker_2_1.write(state_idx2, state_rem2 ++ new_value); \
            } else if (STATE_CELL_FP(state_cell_2_2) == 0) { \
                state_tracker_2_2.write(state_idx2, state_rem2 ++ new_value); \
            } else if (STATE_CELL_FP(state_cell_2_3) == 0) { \
                state_tracker_2_3.write(state_idx2, state_rem2 ++ new_value); \
            } else if (STATE_CELL_FP(state_cell_2_4) == 0) { \
                state_tracker_2_4.write(state_idx2, state_rem2 ++ new_value); \
            } \
        } \
    } \
}

#define update_state_tracker_new_hash(new_value) \
{ \
    bit<32> state_fx; \
    bit<32> state_hash_idx1; \
    bit<32> state_hash_idx2; \
    bit<STATE_FINGERPRINT_BITS> state_hash_rem1; \
    bit<STATE_FINGERPRINT_BITS> state_hash_rem2; \
    get_state_tracker_hash(state_fx) \
    get_state_tracker_locations(state_fx, state_hash_idx1, state_hash_rem1, state_hash_idx2, state_hash_rem2) \
    update_state_tracker(new_value, state_hash_idx1, state_hash_rem1, state_hash_idx2, state_hash_rem2) \
}

/* output (bit<2>) is the stored state, 0 if the flow is not stored */
#define read_state_tracker(output, state_idx1, state_rem1, state_idx2, state_rem2) \
{ \
    declare_state_tracker_cells \
    load_state_tracker_cells(state_idx1, state_idx2) \
    output = 0; \
    if (STATE_CELL_FP(state_cell_1_1) == state_rem1) { \
        output = STATE_CELL_VALUE(state_cell_1_1); \
    } else if (STATE_CELL_FP(state_cell_1_2) == state_rem1) { \
        output = STATE_CELL_VALUE(state_cell_1_2); \
    } else if (STATE_CELL_FP(state_cell_1_3) == state_rem1) { \
        output = STATE_CELL_VALUE(state_cell_1_3); \
    } else if (STATE_CELL_FP(state_cell_1_4) == state_rem1) { \
        output = STATE_CELL_VALUE(state_cell_1_4); \
    } else if (STATE_CELL_FP(state_cell_2_1) == state_rem2) { \
        output = STATE_CELL_VALUE(state_cell_2_1); \
    } else if (STATE_CELL_FP(state_cell_2_2) == state_rem2) { \
        output = STATE_CELL_VALUE(state_cell_2_2); \
    } else if (STATE_CELL_FP(state_cell_2_3) == state_rem2) { \
        output = STATE_CELL_VALUE(state_cell_2_3); \
    } else if (STATE_CELL_FP(state_cell_2_4) == state_rem2) { \
        output = STATE_CELL_VALUE(state_cell_2_4); \
    } \
}

#define read_state_tracker_new_hash(output) \
{ \
    bit<32> state_fx; \
    bit<32> state_hash_idx1; \
    bit<32> state_hash_idx2; \
    bit<STATE_FINGERPRINT_BITS> state_hash_rem1; \
    bit<STATE_FINGERPRINT_BITS> state_hash_rem2; \
    get_state_tracker_hash(state_fx) \
    get_state_tracker_locations(state_fx, state_hash_idx1, state_hash_rem1, state_hash_idx2, state_hash_rem2) \
    read_state_tracker(output, state_hash_idx1, state_hash_rem1, state_hash_idx2, state_hash_rem2) \
}

/* frees the cell of the flow (e.g. on connection close) */
#define delete_state_tracker(state_idx1, state_rem1, state_idx2, state_rem2) \
{ \
    declare_state_tracker_cells \
    load_state_tracker_cells(state_idx1, state_idx2) \
    if (STATE_CELL_FP(state_cell_1_1) == state_rem1) { \
        state_tracker_1_1.write(state_idx1, 0); \
    } else if (STATE_CELL_FP(state_cell_1_2) == state_rem1) { \
        state_tracker_1_2.write(state_idx1, 0); \
    } else if (STATE_CELL_FP(state_cell_1_3) == state_rem1) { \
        state_tracker_1_3.write(state_idx1, 0); \
    } else if (STATE_CELL_FP(state_cell_1_4) == state_rem1) { \
        state_tracker_1_4.write(state_idx1, 0); \
    } else if (STATE_CELL_FP(state_cell_2_1) == state_rem2) { \
        state_tracker_2_1.write(state_idx2, 0); \
    } else if (STATE_CELL_FP(state_cell_2_2) == state_rem2) { \
        state_tracker_2_2.write(state_idx2, 0); \
    } else if (STATE_CELL_FP(state_cell_2_3) == state_rem2) { \
        state_tracker_2_3.write(state_idx2, 0); \
    } else if (STATE_CELL_FP(state_cell_2_4) == state_rem2) { \
        state_tracker_2_4.write(state_idx2, 0); \
    } \
}

#define delete_state_tracker_new_hash \
{ \
    bit<32> state_fx; \
    bit<32> state_hash_idx1; \
    bit<32> state_hash_idx2; \
    bit<STATE_FINGERPRINT_BITS> state_hash_rem1; \
    bit<STATE_FINGERPRINT_BITS> state_hash_rem2; \
    get_state_tracker_hash(state_fx) \
    get_state_tracker_locations(state_fx, state_hash_idx1, state_hash_rem1, state_hash_idx2, state_hash_rem2) \
    delete_state_tracker(state_hash_idx1, state_hash_rem1, state_hash_idx2, state_hash_rem2) \
}


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
