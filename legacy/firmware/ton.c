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

#include "ton.h"
#include "base32.h"
#include "buttons.h"
#include "config.h"
#include "font.h"
#include "fsm.h"
#include "gettext.h"
#include "layout2.h"
#include "messages.h"
#include "messages.pb.h"
#include "protect.h"
#include "sha3.h"
#include "sha512.h"
#include "util.h"

#define V4R2_SIZE 39
#define DATA_PREFIX_SIZE 10
#define SHA256_SIZE 32
#define SIZE_PUBKEY 65

static const uint8_t TON_WALLET_CODE_HASH_V4R2[V4R2_SIZE] = {
    0x02, 0x01, 0x34, 0x00, 0x07, 0x00, 0x00, 0xfe,
    0xb5, 0xff, 0x68, 0x20, 0xe2, 0xff, 0x0d, 0x94,
    0x83, 0xe7, 0xe0, 0xd6, 0x2c, 0x81, 0x7d, 0x84,
    0x67, 0x89, 0xfb, 0x4a, 0xe5, 0x80, 0xc8, 0x78,
    0x86, 0x6d, 0x95, 0x9d, 0xab, 0xd5, 0xc0
};

// "0051" + "0000 0000"+ wallet_id(-1 if testnet)
static const uint8_t TON_WALLET_DATA_HASH_PREFIX[DATA_PREFIX_SIZE] = {
    0x00, 0x51, 0x00, 0x00, 0x00, 0x00, 0x29, 0xa9,
    0xa3, 0x17
};

void ton_append_data_cell_hash(const uint8_t *public_key, SHA3_CTX *ctx) {
    uint8_t data_hash[SHA256_SIZE] = {0};
    struct SHA3_CTX ctx_data = {0};

    sha3_256_Init(&ctx_data);
    
    sha3_Update(&ctx_data, TON_WALLET_DATA_HASH_PREFIX, DATA_PREFIX_SIZE);
    sha3_Update(&ctx_data, public_key, SIZE_PUBKEY);
    sha3_Update(&ctx_data, (const uint8_t *)"\x40", 1);
    sha3_Final(&ctx_data, data_hash);
    
    // append data cell hash to buf
    sha3_Update(ctx, data_hash, SHA256_SIZE);
}

void ton_get_address_from_public_key(const uint8_t *public_key,
                                       char *address) {
    uint8_t buf[SHA256_SIZE] = {0};
    struct SHA3_CTX ctx = {0};

    sha3_256_Init(&ctx);

    //append descripter prefix and code cell hash
    sha3_Update(&ctx, TON_WALLET_CODE_HASH_V4R2, V4R2_SIZE);

    sha3_Final(&ctx, buf);
    address[0] = '0';
    address[1] = 'x';
    data2hexaddr((const uint8_t *)buf, SHA256_SIZE, address + 2);
}