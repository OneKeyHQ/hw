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

#ifndef __TON_H__
#define __TON_H__

#include <stdbool.h>
#include <stdint.h>
#include "bip32.h"
#include "messages-ton.pb.h"

/**
 * Size of Public key in bytes
 */
void ton_to_user_friendly(TonWorkChain workchain,
                          const char *hash,
                          bool is_bounceable,
                          bool is_testnet_only,
                          char *address);

void ton_get_address_from_public_key(const uint8_t *public_key,
                                       TonWorkChain workchain,
                                       bool is_bounceable,
                                       bool is_testnet_only,
                                       char *address);

bool ton_sign_message(const TonSignMessage *msg, const HDNode *node,
                        TonSignedMessage *resp);

bool ton_sign_proof(const TonSignProof *msg, const HDNode *node,
                        TonSignedProof *resp);

uint16_t crc16(uint8_t *ptr, size_t count);

bool base64_decode (char *ctx,
	       const char *restrict in, size_t inlen,
	       char *restrict out, size_t *outlen);
#endif  // __TON_H__