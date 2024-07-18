#include <stdbool.h>

#include "ton_cell.h"
#include "sha2.h"
#include "messages.h"
#include "messages.pb.h"
#include "messages-ton.pb.h"
#include "util.h"

#define SAFE(RES)         \
    if ((RES) != CX_OK) { \
        return false;     \
    }

bool ton_hash_cell(BitString_t *bits, CellRef_t *refs, uint8_t refs_count, CellRef_t *out) {

    SHA256_CTX ctx;
    sha256_Init(&ctx);

    // Data and descriptors
    uint16_t len = bits->data_cursor;
    uint8_t d1 = refs_count;                     // refs descriptor
    uint8_t d2 = (len >> 3) + ((len + 7) >> 3);  // bits descriptor
    uint8_t d[2] = {d1, d2};
    bitstring_final(bits);

    sha256_Update(&ctx, d, 2);
    sha256_Update(&ctx, bits->data, bits->data_cursor / 8);

    // Hash ref depths
    for (int i = 0; i < refs_count; i++) {
        struct CellRef_t md = refs[i];
        uint8_t mdd[2] = {md.max_depth / 256, md.max_depth % 256};
        sha256_Update(&ctx, mdd, 2);

    }

    // Hash ref digests
    for (int i = 0; i < refs_count; i++) {
        struct CellRef_t md = refs[i];
        sha256_Update(&ctx, md.hash, HASH_LEN);
    }

    // Finalize
    sha256_Final(&ctx, out->hash);

    // Depth
    out->max_depth = 0;
    if (refs_count > 0) {
        for (int i = 0; i < refs_count; i++) {
            struct CellRef_t md = refs[i];
            if (md.max_depth > out->max_depth) {
                out->max_depth = md.max_depth;
            }
        }
        out->max_depth = out->max_depth + 1;
    }

    return true;
}

bool ton_create_transfer_body(const char *memo, CellRef_t* payload) {
    if (memo == NULL || strlen(memo) == 0) {
        return false;
    }

    BitString_t bits;
    
    bitstring_init(&bits);
    bitstring_write_uint(&bits, 0, 32);  // text comment tag
    bitstring_write_buffer(&bits, (uint8_t *)memo, strlen(memo));

    ton_hash_cell(&bits, NULL, 0, payload);
    return true;
}

bool ton_create_jetton_transfer_body(uint8_t dest_workchain, uint8_t* dest_hash, uint64_t jetton_value, uint64_t forward_amount, const char *forward_payload,
                                    uint8_t resp_workchain, uint8_t* resp_hash, CellRef_t* payload) {
    BitString_t bits;
    
    bitstring_init(&bits);
    bitstring_write_uint(&bits, 0xf8a7ea5, 32);                  // jetton transfer op-code
    bitstring_write_uint(&bits, 0, 64);                          // query id
    bitstring_write_coins(&bits, jetton_value);
    bitstring_write_address(&bits, dest_workchain, dest_hash);   // to addr
    bitstring_write_address(&bits, resp_workchain, resp_hash);   // response addr
    bitstring_write_bit(&bits, 0);                               // no custom payload
    bitstring_write_coins(&bits, forward_amount);                // forward amount
    bitstring_write_bit(&bits, 0);                               // forward payload in this cell, not separate
    if (forward_payload != NULL) bitstring_write_buffer(&bits, (uint8_t *)forward_payload, strlen(forward_payload));
    
    ton_hash_cell(&bits, NULL, 0, payload);
    return true;
}

bool ton_create_message_digest(uint32_t expire_at, uint32_t seqno, bool is_bounceable, uint8_t dest_workchain, uint8_t* dest_hash, 
                                uint64_t value, uint8_t mode, CellRef_t* init, CellRef_t* payload, uint8_t* digest) {

    BitString_t bits;
    struct CellRef_t payload_ref;
    struct CellRef_t state_init_ref;

    //
    // Internal Message
    //

    struct CellRef_t internalMessageRef;
    bitstring_init(&bits);
    bitstring_write_bit(&bits, 0);                                // tag
    bitstring_write_bit(&bits, 1);                                // ihr_disabled
    bitstring_write_bit(&bits, is_bounceable ? 1 : 0);            // bounce
    bitstring_write_bit(&bits, 0);                                // bounced
    bitstring_write_null_address(&bits);                           // from
    bitstring_write_address(&bits, dest_workchain, dest_hash);    // to
    // amount
    bitstring_write_coins(&bits, value);
    bitstring_write_bit(&bits, 0);       // Currency collection (not supported)
    bitstring_write_coins(&bits, 0);     // ihr_fees
    bitstring_write_coins(&bits, 0);     // fwd_fees
    bitstring_write_uint(&bits, 0, 64);  // CreatedLT
    bitstring_write_uint(&bits, 0, 32);  // CreatedAt

    // Refs
    if ((init!=NULL) && (payload!=NULL)) {
        bitstring_write_bit(&bits, 1);  // state-init
        bitstring_write_bit(&bits, 1);  // state-init ref
        bitstring_write_bit(&bits, 1);  // body in ref

        // Create refs
        payload_ref.max_depth = payload->max_depth;
        memmove(payload_ref.hash, payload->hash, HASH_LEN);
        state_init_ref.max_depth = init->max_depth;
        memmove(state_init_ref.hash, init->hash, HASH_LEN);

        // Hash cell
        struct CellRef_t internalMessageRefs[2] = {state_init_ref, payload_ref};
        if (!ton_hash_cell(&bits, internalMessageRefs, 2, &internalMessageRef)) {
            return false;
        }
    } else if (payload!=NULL) {
        bitstring_write_bit(&bits, 0);  // no state-init
        bitstring_write_bit(&bits, 1);  // body in ref

        // Create ref
        payload_ref.max_depth = payload->max_depth;
        memmove(payload_ref.hash,payload->hash, HASH_LEN);

        // Hash cell
        struct CellRef_t internalMessageRefs[1] = {payload_ref};
        if (!ton_hash_cell(&bits, internalMessageRefs, 1, &internalMessageRef)) {
            return false;
        }
    } else if (init!=NULL) {
        bitstring_write_bit(&bits, 1);  // state-init
        bitstring_write_bit(&bits, 1);  // state-init ref
        bitstring_write_bit(&bits, 0);  // body inline

        // Create ref
        state_init_ref.max_depth = init->max_depth;
        memmove(state_init_ref.hash, init->hash, HASH_LEN);

        // Hash cell
        struct CellRef_t internalMessageRefs[1] = {state_init_ref};
        if (!ton_hash_cell(&bits, internalMessageRefs, 1, &internalMessageRef)) {
            return false;
        }
    } else {
        bitstring_write_bit(&bits, 0);  // no state-init
        bitstring_write_bit(&bits, 0);  // body inline

        // Hash cell
        if (!ton_hash_cell(&bits, NULL, 0, &internalMessageRef)) {
            return false;
        }
    }

    //
    // Order
    //

    struct CellRef_t orderRef;
    bitstring_init(&bits);
    bitstring_write_uint(&bits, 698983191, 32);     // Wallet ID
    bitstring_write_uint(&bits, expire_at, 32);     // Timeout
    bitstring_write_uint(&bits, seqno, 32);         // Seqno
    bitstring_write_uint(&bits, 0, 8);              // Simple order
    bitstring_write_uint(&bits, mode, 8);           // Send Mode

    struct CellRef_t orderRefs[1] = {internalMessageRef};
    if (!ton_hash_cell(&bits, orderRefs, 1, &orderRef)) {
        return false;
    }

    // Result
    memmove(digest, orderRef.hash, HASH_LEN);

    return true;
}