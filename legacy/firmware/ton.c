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
#include "sha2.h"
#include "util.h"
#include <stdio.h>
#include "base64.h"
#include "ton_bits.h"
#include "ton_cell.h"
#include "ton_tokens.h"
// #include "algo/base64.h"

#define V4R2_SIZE 39
#define DATA_PREFIX_SIZE 10
#define SHA256_SIZE 32
#define SIZE_PUBKEY 32
#define USER_FRIENDLY_LEN 36
#define USER_FRIENDLY_B64_LEN 48

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

typedef struct {
    uint32_t workchain;
    uint8_t hash[32];
    bool is_bounceable;
    bool is_testnet_only;
} TON_PARSED_ADDRESS;

static inline unsigned char to_uchar(char ch) { return ch; }

void ton_base64_encode(const char *restrict in, size_t inlen, char *restrict out,
                   size_t outlen) {
    static const char b64str[64] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    while (inlen && outlen) {
        *out++ = b64str[(to_uchar(in[0]) >> 2) & 0x3f];
        if (!--outlen) break;
        *out++ =
            b64str[((to_uchar(in[0]) << 4) + (--inlen ? to_uchar(in[1]) >> 4 : 0)) &
                    0x3f];
        if (!--outlen) break;
        *out++ = (inlen ? b64str[((to_uchar(in[1]) << 2) +
                                    (--inlen ? to_uchar(in[2]) >> 6 : 0)) &
                                    0x3f]
                        : '=');
        if (!--outlen) break;
        *out++ = inlen ? b64str[to_uchar(in[2]) & 0x3f] : '=';
        if (!--outlen) break;
        if (inlen) inlen--;
        if (inlen) in += 3;
    }

    if (outlen) *out = '\0';
}

void ton_append_data_cell_hash(const uint8_t *public_key, SHA256_CTX *ctx) {
    uint8_t data_hash[SHA256_SIZE] = {0};
    SHA256_CTX ctx_data;

    sha256_Init(&ctx_data);

    sha256_Update(&ctx_data, TON_WALLET_DATA_HASH_PREFIX, DATA_PREFIX_SIZE);
    sha256_Update(&ctx_data, public_key, 32);
    sha256_Update(&ctx_data, (const uint8_t *)"\x40", 1);

    sha256_Final(&ctx_data, data_hash);

    // append data cell hash to buf
    sha256_Update(ctx, data_hash, SHA256_SIZE);
}

void ton_get_address_from_public_key(const uint8_t *public_key,
                                       TonWorkChain workchain,
                                       bool is_bounceable,
                                       bool is_testnet_only,
                                       char *address) {
    SHA256_CTX ctx;
    sha256_Init(&ctx);

    //append descripter prefix and code cell hash
    sha256_Update(&ctx, TON_WALLET_CODE_HASH_V4R2, V4R2_SIZE);

    ton_append_data_cell_hash(public_key, &ctx);

    sha256_Final(&ctx, (uint8_t*)address);

}

void ton_to_user_friendly(TonWorkChain workchain,
                          const char *hash,
                          bool is_bounceable,
                          bool is_testnet_only,
                          char *output) {
    
    char address[36] = {0};
    // Address Tag
    if (is_bounceable) {
        address[0] = 0x11;  // Bounceable
    } else {
        address[0] = 0x51;  // Non-Bounceable
    }
    if (is_testnet_only) {
        address[0] = address[0] | 0x80;
    }

    // Workchain
    address[1] = (workchain == TonWorkChain_BASECHAIN) ? 0x00 : 0xff;

    // Hash
    memmove(address + 2, hash, 32);

    // crc16
    uint16_t crc = crc16((uint8_t *)address, 34);
    address[34] = (crc >> 8) & 0xff;
    address[35] = crc & 0xff;

    // Base64
    ton_base64_encode(address, sizeof(address), output, USER_FRIENDLY_B64_LEN);

}

uint16_t crc16(uint8_t *ptr, size_t count) {
    size_t crc = 0;
    int counter = count;
    int i = 0;
    while (--counter >= 0) {
        crc = crc ^ (size_t) *ptr++ << 8;
        i = 8;
        do {
            if (crc & 0x8000) {
                crc = crc << 1 ^ 0x1021;
            } else {
                crc = crc << 1;
            }
        } while (--i);
    }
    return (crc);
}

void ton_parse_addr(const char *dest, TON_PARSED_ADDRESS *parsed_addr) {
    // Base64
    uint8_t decode_res[36];
    ton_base64_decode(dest, USER_FRIENDLY_B64_LEN, decode_res, USER_FRIENDLY_LEN);

    // Flag
    uint8_t flag = decode_res[0];
    parsed_addr->is_bounceable = false;
    parsed_addr->is_testnet_only = false;
    if (flag & 0x80) {
        parsed_addr->is_testnet_only = true;
        flag ^= 0x80;
    }
    if (flag == 0x11) {
        parsed_addr->is_bounceable = true;
    } else if (flag != 0x51) {
        // printf("error");
    }

    // Workchain
    parsed_addr->workchain = decode_res[1];
    // Hash
    memmove(parsed_addr->hash, decode_res + 2, 32);
}

void ton_format_toncoin_amount(const uint64_t amount, char *buf, int buflen) {
    char str_amount[40] = {0};
    bn_format_uint64(amount, NULL, NULL, 9, 0, false, 0, str_amount,
                    sizeof(str_amount));
    snprintf(buf, buflen, "%s TON", str_amount);
}

void ton_format_jetton_amount(const uint64_t amount, char *buf, int buflen, int decimals, const char* jetton_name) {
    char str_amount[40] = {0};
    bn_format_uint64(amount, NULL, NULL, decimals, 0, false, 0, str_amount,
                    sizeof(str_amount));

    snprintf(buf, buflen, "%s %s", str_amount, jetton_name);
}

void ton_get_jetton_name(char *jetton_master_address, char *jetton_name) {
    // get jetton name
};

bool ton_sign_message(const TonSignMessage *msg, const HDNode *node,
                        TonSignedMessage *resp) {

    // get address
    char raw_address[32] = {0};
    char usr_friendly_address[49] = {0};
    ton_get_address_from_public_key(node->public_key + 1, msg->workchain, msg->is_bounceable, msg->is_testnet_only, raw_address);
    ton_to_user_friendly(msg->workchain, (const char*)raw_address, msg->is_bounceable, msg->is_testnet_only, usr_friendly_address);

    // display
    if(msg->jetton_amount == 0) {
        char amount_str[60];
        ton_format_toncoin_amount(msg->ton_amount, amount_str, sizeof(amount_str));
        if (msg->has_comment) {
            if (!layoutTransactionSign("Ton", 0, false, amount_str, msg->destination, usr_friendly_address, NULL, NULL, NULL, 0,
                                    "Memo", msg->comment, NULL, NULL, NULL, NULL, NULL, NULL)) {
                fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
                layoutHome();
                return false;
            }
        } else {
            if (!layoutTransactionSign("Ton", 0, false, amount_str, msg->destination, usr_friendly_address, NULL, NULL, NULL, 0,
                                    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
                fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
                layoutHome();
                return false;
            }
        }
        
        // parse dest addr
        TON_PARSED_ADDRESS parsed_addr = {0};
        ton_parse_addr(msg->destination, &parsed_addr);

        // prepare body ref
        CellRef_t *payload;
        payload = (CellRef_t *)malloc(sizeof(CellRef_t));
        if (!ton_create_transfer_body(msg->comment, payload)) {
            payload = NULL;
        }
        
        // create message digest
        uint8_t digest[32] = {0};
        ton_create_message_digest(msg->expire_at, msg->seqno, parsed_addr.is_bounceable, parsed_addr.workchain, parsed_addr.hash ,
                                    msg->ton_amount, msg->mode, NULL, payload, digest);

        ed25519_sign((const unsigned char*)digest, SHA256_SIZE, node->private_key,
                resp->signature.bytes);
        resp->signature.size = 64;

    } else {
        ConstTonTokenPtr token = NULL;
        token = ton_get_token_by_address(msg->jetton_master_address);

        char amount_str[60];
        ton_format_jetton_amount(msg->jetton_amount, amount_str, sizeof(amount_str), token->decimals, token->name);
        if (msg->has_comment) {
            if (!layoutTransactionSign("Ton", 0, true, amount_str, msg->destination, usr_friendly_address, NULL, NULL, NULL, 0,
                                    "Memo", msg->comment, "Token Contract:", msg->jetton_master_address, NULL, NULL, NULL, NULL)) {
                fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
                layoutHome();
                return false;
            }
        } else {
            if (!layoutTransactionSign("Ton", 0, true, amount_str, msg->destination, usr_friendly_address, NULL, NULL, NULL, 0,
                                    "Token Contract:", msg->jetton_master_address, NULL, NULL, NULL, NULL, NULL, NULL)) {
                fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
                layoutHome();
                return false;
            }
        }
        
        // parse dest&resp addr
        TON_PARSED_ADDRESS parsed_dest, parsed_resp = {0};
        ton_parse_addr(msg->destination, &parsed_dest);
        ton_parse_addr(usr_friendly_address, &parsed_resp);

        // prepare body ref
        CellRef_t *payload;
        payload = (CellRef_t *)malloc(sizeof(CellRef_t));
        if (!msg->has_comment) {
            ton_create_jetton_transfer_body(parsed_dest.workchain, parsed_dest.hash, msg->jetton_amount, 0, NULL,
                                    parsed_resp.workchain, parsed_resp.hash, payload);
        } else {
            ton_create_jetton_transfer_body(parsed_dest.workchain, parsed_dest.hash, msg->jetton_amount, msg->fwd_fee, msg->comment,
                                    parsed_resp.workchain, parsed_resp.hash, payload);
        }

    
        // create message digest
        uint8_t digest[64] = {0};
        ton_create_message_digest(msg->expire_at, msg->seqno, parsed_dest.is_bounceable, parsed_dest.workchain, parsed_dest.hash ,
                                    msg->ton_amount, msg->mode, NULL, payload, digest);
        ed25519_sign((const unsigned char*)digest, SHA256_SIZE, node->private_key,
                resp->signature.bytes);
        resp->signature.size = 64;

    }

    return true;
}

bool ton_sign_proof(const TonSignProof *msg, const HDNode *node,
                        TonSignedProof *resp) {
    printf("ton_sign_proof\n");

    // get address
    char raw_address[32] = {0};
    char usr_friendly_address[49] = {0};
    ton_get_address_from_public_key(node->public_key + 1, msg->workchain, msg->is_bounceable, msg->is_testnet_only, raw_address);
    ton_to_user_friendly(msg->workchain, (const char*)raw_address, msg->is_bounceable, msg->is_testnet_only, usr_friendly_address);
    
    if (!fsm_layoutSignMessage("Ton", (const char*)usr_friendly_address, msg->comment.bytes,
                             msg->comment.size)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return false;
    }

    // hash 1
    SHA256_CTX ctx;
    sha256_Init(&ctx);

    const char *message_header = "ton-proof-item-v2/";
    sha256_Update(&ctx, (const uint8_t*)message_header, 18);

    int32_t workchain = (msg->workchain == TonWorkChain_BASECHAIN) ? 0 : -1;
    int32_t *workchain_ptr = &workchain;
    const uint8_t *wc = (const uint8_t *)workchain_ptr;
    sha256_Update(&ctx, wc, 4);

    sha256_Update(&ctx, (const uint8_t *)raw_address, 32);

    uint32_t domain_len = msg->appdomain.size;
    sha256_Update(&ctx, (const uint8_t *)&domain_len, 4);

    sha256_Update(&ctx, (const uint8_t *)msg->appdomain.bytes, domain_len);

    sha256_Update(&ctx, (const uint8_t *)&msg->expire_at, 8);

    uint32_t comment_len = msg->comment.size;
    sha256_Update(&ctx, (const uint8_t *)msg->comment.bytes, comment_len);

    uint8_t *message[32] = {0};
    sha256_Final(&ctx, (uint8_t*)message);
   
    /********* test **********/
    char message_hex[65] = {0};
    data2hexaddr((const uint8_t *)message, 32, message_hex);
    printf("\nmessage 1: %s", message_hex);
    /*************************/

    // hash 2
    sha256_Init(&ctx);
    sha256_Update(&ctx, (const uint8_t *)"\xff\xff", 2);

    const char *message_final_header = "ton-connect";
    sha256_Update(&ctx, (const uint8_t*)message_final_header, 11);
    /********* test **********/
    char tmp0[22] = {0};
    data2hexaddr((const uint8_t *)message_final_header, 11, tmp0);
    printf("\nheader: %s", tmp0);
    /*************************/

    sha256_Update(&ctx, (const uint8_t *)message, 32);
    // /********* test **********/
    // char message_hex[65] = {0};
    // data2hexaddr((const uint8_t *)message, 32, message_hex);
    // printf("\nmessage 1: %s", message_hex);
    // /*************************/

    uint8_t *message_final[32] = {0};
    sha256_Final(&ctx, (uint8_t*)message_final);

    /********* test **********/
    char message_final_hex[65] = {0};
    data2hexaddr((const uint8_t *)message_final, 32, message_final_hex);
    printf("\nmessage_final: %s", message_final_hex);
    /*************************/

    ed25519_sign((const unsigned char*)message_final, SHA256_SIZE, node->private_key,
            resp->signature.bytes);
    resp->signature.size = 64;

    /********* test **********/
    char sig[128] = {0};
    data2hexaddr((const uint8_t *)resp->signature.bytes, 64, sig);
    printf("\nsig: %s\n", sig);
    /*************************/

    return true;
}