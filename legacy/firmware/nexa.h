
#ifndef __NEXA_H__
#define __NEXA_H__
#include "bip32.h"
#include "messages-nexa.pb.h"

void nexa_get_address(uint8_t *pubkey, const uint8_t pubkey_len,
                      const char *prefix, char *addr);
void nexa_sign_sighash(HDNode *node, const uint8_t *raw_message,
                       uint32_t raw_message_len, uint8_t *signature,
                       pb_size_t *signature_len);
void nexa_signing_init(const NexaSignTx *msg);
void nexa_signing_abort(void);

extern uint16_t input_count_nexa;
extern uint16_t input_index_nexa;
#endif  // __NEXA_H__
