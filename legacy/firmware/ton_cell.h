#include "ton_bits.h"

typedef struct CellRef_t {
    uint16_t max_depth;
    uint8_t hash[HASH_LEN];
} CellRef_t;

bool ton_create_transfer_body(const char *memo, CellRef_t* payload);

bool ton_create_jetton_transfer_body(uint8_t dest_workchain, uint8_t* dest_hash, uint64_t jetton_value, uint64_t forward_amount, const char *forward_payload,
                                    uint8_t resp_workchain, uint8_t* resp_hash, CellRef_t* payload);

bool ton_create_message_digest(uint32_t expire_at, uint32_t seqno, bool is_bounceable, uint8_t dest_workchain, uint8_t* dest_hash, 
                                uint64_t value, uint8_t mode,CellRef_t* init, CellRef_t* payload, uint8_t* digest);