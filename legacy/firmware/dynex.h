/*
 * This file is part of the OneKey project, https://onekey.so/
 *
 * Copyright (C) 2021 OneKey Team <core@onekey.so>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "bip32.h"
#include "messages-dynex.pb.h"
#include "monero/monero.h"

#define MAX_INPUTS_COUNT 10
extern bool dnx_signing;
extern uint8_t dnx_input_index;
extern uint8_t dnx_inputs_count;
extern ge25519 spend_pub_key;
extern bignum256modm spend_sec_key;
extern ge25519 view_pub_key;
extern bignum256modm view_sec_key;
extern bignum256modm tx_sec_key;
extern uint8_t tx_pub_key_bytes[32];
extern char destination[98];
extern uint64_t total_input_amounts;
extern uint64_t amounts;
extern uint64_t fee;
extern bool key_image_synced;
extern Hasher dnx_hasher_context;
extern uint8_t output_keys[MAX_INPUTS_COUNT][32];
extern uint8_t key_images[MAX_INPUTS_COUNT][32];
extern uint8_t ephemeral_keys[MAX_INPUTS_COUNT][32];
extern uint8_t payment_id[32];
extern bool has_payment_id;
void decodeint(bignum256modm recovery_key, const uint8_t* in);
void encodeint(uint8_t* out, const bignum256modm recovery_key);
void decodepoint(ge25519* point, const uint8_t* in);
void encodepoint(uint8_t* out, const ge25519* point);
void generate_keys(const uint8_t* seed, ge25519* pub_key,
                   bignum256modm sec_key);
void dnx_encode_addr(char* addr, const uint8_t tag, const ge25519* spend_pub,
                     const ge25519* view_pub);
int dnx_base58_addr_decode_check(const char* addr, size_t sz, void* data,
                                 size_t datalen);
void dnx_get_address(char* addr, const uint8_t* key_seed, bool cache_keys);
void dnx_singing_init(const DnxSignTx* msg);
void dnx_singing_abort(void);
void dnx_generate_key_image(const ge25519* tx_pub_key, const ge25519* s_pub_key,
                            const bignum256modm s_sec_key, const uint32_t idx,
                            const bignum256modm v_sec_key, uint8_t* key_img,
                            uint8_t* eph_secret_key);
void dnx_generate_output_key(uint8_t* output_key, const uint32_t output_idx,
                             const bignum256modm t_sec_key,
                             const ge25519* v_pub_key,
                             const ge25519* s_pub_key);
void generate_ring_signature(const uint8_t* prefix_hash,
                             const ge25519* key_image, const uint8_t n,
                             const ge25519 pubs[n], const bignum256modm sec_key,
                             const uint8_t sec_idx, bignum256modm sigs[n][2]);
bool layoutDnxTxInfo(const DnxSignTx* msg, const HDNode* node);
void dnx_get_tracking_key(uint8_t* tracking_key);
bool layoutDnxGetTrackingKey(const char* addr);
