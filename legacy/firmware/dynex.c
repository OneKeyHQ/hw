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
#include "dynex.h"
#include <stdint.h>
#include "buttons.h"
#include "fsm.h"
#include "gettext.h"
#include "layout2.h"
#include "memzero.h"
#include "messages.h"
#include "monero/monero.h"
#include "protect.h"
#include "util.h"

static const uint8_t DNX_ADDR_TAG = 0xB9;
bool dnx_signing = false;
uint8_t dnx_inputs_count = 0;
uint8_t dnx_input_index = 0;
uint64_t total_input_amounts = 0;
uint64_t amounts = 0;
uint64_t fee = 0;
char destination[98] = {0};
ge25519 spend_pub_key = {0};
bignum256modm spend_sec_key = {0};
ge25519 view_pub_key = {0};
bignum256modm view_sec_key = {0};
bignum256modm tx_sec_key = {0};
uint8_t tx_pub_key_bytes[32] = {0};
bool key_image_synced = false;
Hasher dnx_hasher_context = {0};
uint8_t output_keys[MAX_INPUTS_COUNT][32],
    key_images[MAX_INPUTS_COUNT][32] = {0};
uint8_t ephemeral_keys[MAX_INPUTS_COUNT][32] = {0};
uint8_t payment_id[32] = {0};
bool has_payment_id = false;
static int dnx_base58_addr_encode_check(uint64_t tag, const uint8_t* data,
                                        size_t binsz, char* b58, size_t b58sz);

void decodeint(bignum256modm recovery_key, const uint8_t* in) {
  set256_modm(recovery_key, 0);
  expand256_modm(recovery_key, in, 32);
}
void encodeint(uint8_t* out, const bignum256modm recovery_key) {
  contract256_modm(out, recovery_key);
}
void decodepoint(ge25519* point, const uint8_t* in) {
  ge25519_unpack_vartime(point, in);
}
void encodepoint(uint8_t* out, const ge25519* point) {
  ge25519_pack(out, point);
}

void generate_keys(const uint8_t* seed, ge25519* pub_key,
                   bignum256modm sec_key) {
  decodeint(sec_key, seed);
  ge25519_set_neutral(pub_key);
  ge25519_scalarmult_base_wrapper(pub_key, sec_key);
}

void dnx_generate_key_image(const ge25519* tx_pub_key, const ge25519* s_pub_key,
                            const bignum256modm s_sec_key, const uint32_t idx,
                            const bignum256modm v_sec_key, uint8_t* key_img,
                            uint8_t* eph_secret_key) {
  ge25519 recv_derivation = {0};
  ge25519 eph_pub_key = {0};
  ge25519_set_neutral(&recv_derivation);
  ge25519_set_neutral(&eph_pub_key);
  xmr_generate_key_derivation(&recv_derivation, tx_pub_key, v_sec_key);
  xmr_derive_public_key(&eph_pub_key, &recv_derivation, idx, s_pub_key);
  bignum256modm eph_sec_key = {0};
  xmr_derive_private_key(eph_sec_key, &recv_derivation, idx, s_sec_key);
  ge25519 point = {0};
  ge25519 point2 = {0};
  ge25519_set_neutral(&point);
  ge25519_set_neutral(&point2);
  uint8_t out[32] = {0};
  encodepoint(out, &eph_pub_key);
  xmr_hash_to_ec(&point, out, sizeof(out));
  ge25519_scalarmult(&point2, &point, eph_sec_key);
  encodepoint(key_img, &point2);
  encodeint(eph_secret_key, eph_sec_key);
  // encodepoint(eph_pub, &eph_pub_key);
  return;
}

void dnx_generate_output_key(uint8_t* output_key, const uint32_t output_idx,
                             const bignum256modm t_sec_key,
                             const ge25519* v_pub_key,
                             const ge25519* s_pub_key) {
  ge25519 derivation = {0};
  ge25519_set_neutral(&derivation);
  ge25519 out_eph_pub_key = {0};
  ge25519_set_neutral(&out_eph_pub_key);
  xmr_generate_key_derivation(&derivation, v_pub_key, t_sec_key);
  xmr_derive_public_key(&out_eph_pub_key, &derivation, output_idx, s_pub_key);
  encodepoint(output_key, &out_eph_pub_key);
  return;
}
void dnx_encode_addr(char* addr, const uint8_t tag, const ge25519* spend_pub,
                     const ge25519* view_pub) {
  uint8_t payload[64] = {0};
  encodepoint(payload, spend_pub);
  encodepoint(payload + 32, view_pub);
  dnx_base58_addr_encode_check(tag, payload, sizeof(payload), addr, 98);
}
static int dnx_base58_addr_encode_check(uint64_t tag, const uint8_t* data,
                                        size_t binsz, char* b58, size_t b58sz) {
  size_t b58size = b58sz;
  uint8_t size = xmr_size_varint(tag);
  uint8_t buf[(binsz + size) + HASHER_DIGEST_LENGTH];
  memset(buf, 0, sizeof(buf));
  xmr_write_varint(buf, sizeof(buf), tag);
  uint8_t* hash = buf + binsz + size;
  memcpy(buf + size, data, binsz);
  hasher_Raw(HASHER_SHA3K, buf, binsz + size, hash);

  bool r = xmr_base58_encode(b58, &b58size, buf, binsz + size + 4);
  return (int)(!r ? 0 : b58size);
}

int dnx_base58_addr_decode_check(const char* addr, size_t sz, void* data,
                                 size_t datalen) {
  size_t buflen = 2 + 64 + 4;
  uint8_t buf[buflen];
  memzero(buf, sizeof(buf));
  uint8_t hash[HASHER_DIGEST_LENGTH] = {0};

  if (!xmr_base58_decode(addr, sz, buf, &buflen)) {
    return 0;
  }

  if (buflen <= 4 + 1) {
    return 0;
  }

  size_t res_size = buflen - 4 - 2;
  if (datalen < res_size) {
    return 0;
  }

  hasher_Raw(HASHER_SHA3K, buf, buflen - 4, hash);
  if (memcmp(hash, buf + buflen - 4, 4) != 0) {
    return 0;
  }
  uint64_t tag;
  xmr_read_varint(buf, 2, &tag);
  if (tag != DNX_ADDR_TAG) {
    return false;
  }

  memcpy(data, buf + 2, res_size);
  return (int)res_size;
}

void dnx_get_address(char* addr, const uint8_t* key_seed, bool cache_keys) {
  bignum256modm spend_sec = {0};
  ge25519 spend_pub = {0};
  generate_keys(key_seed, &spend_pub, spend_sec);
  uint8_t out[32] = {0};
  encodeint(out, spend_sec);
  uint8_t hash[32] = {0};
  xmr_fast_hash(hash, out, 32);
  bignum256modm view_sec = {0};
  ge25519 view_pub = {0};
  generate_keys(hash, &view_pub, view_sec);
  dnx_encode_addr(addr, DNX_ADDR_TAG, &spend_pub, &view_pub);
  if (cache_keys) {
    spend_pub_key = spend_pub;
    view_pub_key = view_pub;
    memcpy(spend_sec_key, spend_sec, sizeof(spend_sec));
    memcpy(view_sec_key, view_sec, sizeof(view_sec));
  }
}

void dnx_singing_init(const DnxSignTx* msg) {
  dnx_signing = true;
  dnx_inputs_count = msg->inputs_count;
  dnx_input_index = 0;
  total_input_amounts = 0;
  amounts = msg->amount;
  fee = msg->fee;
  key_image_synced = false;
  if (msg->has_payment_id) {
    has_payment_id = true;
    memcpy(payment_id, msg->payment_id.bytes, 32);
  }
  memzero(tx_pub_key_bytes, sizeof(tx_pub_key_bytes));
  memcpy(destination, msg->to_address, 98);
  memzero(&spend_pub_key, sizeof(spend_pub_key));
  memzero(spend_sec_key, sizeof(spend_sec_key));
  memzero(&view_pub_key, sizeof(view_pub_key));
  memzero(view_sec_key, sizeof(view_sec_key));
  memzero(tx_sec_key, sizeof(tx_sec_key));
  xmr_hasher_init(&dnx_hasher_context);
}
void dnx_singing_abort(void) {
  if (!dnx_signing) {
    return;
  }
  dnx_signing = false;
  dnx_inputs_count = 0;
  dnx_input_index = 0;
  total_input_amounts = 0;
  amounts = 0;
  fee = 0;
  key_image_synced = false;
  has_payment_id = false;
  memzero(payment_id, sizeof(payment_id));
  memzero(tx_pub_key_bytes, sizeof(tx_pub_key_bytes));
  memzero(destination, sizeof(destination));
  memzero(&spend_pub_key, sizeof(spend_pub_key));
  memzero(spend_sec_key, sizeof(spend_sec_key));
  memzero(&view_pub_key, sizeof(view_pub_key));
  memzero(view_sec_key, sizeof(view_sec_key));
  memzero(tx_sec_key, sizeof(tx_sec_key));
  memzero(&dnx_hasher_context, sizeof(dnx_hasher_context));
  layoutHome();
}

void dnx_format_amount(const uint64_t amount, char* buf, int buflen) {
  bn_format_uint64(amount, NULL, " DNX", 9, 0, false, ',', buf, buflen);
}

bool layoutDnxTxInfo(const DnxSignTx* msg, const HDNode* node) {
  bool result = false;
  int index = 0;
  int y = 0;
  uint8_t max_index = 0;
  char amount_str[40] = {0};
  char fee_str[20] = {0};
  char from_str[98] = {0};
  dnx_get_address(from_str, node->private_key, true);
  dnx_format_amount(msg->amount, amount_str, sizeof(amount_str));
  dnx_format_amount(msg->fee, fee_str, sizeof(fee_str));
  const char** tx_msg = format_tx_message("Dynex");

  ButtonRequest resp = {0};
  memzero(&resp, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = ButtonRequestType_ButtonRequest_ProtectCall;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);
  if (msg->has_payment_id) {
    max_index = 5;
  } else {
    max_index = 4;
  }
refresh_menu:
  layoutSwipe();
  oledClear();
  y = 13;
  uint8_t bubble_key = KEY_NULL;
  if (index == 0) {
    layoutHeader(tx_msg[0]);
    char desc[8] = {0};
    strcat(desc, _("Amount"));
    strcat(desc, ":");
    oledDrawStringAdapter(0, y, desc, FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, amount_str, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 1) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, _("Send to:"), FONT_STANDARD);
    bubble_key = oledDrawPageableStringAdapter(
        0, y + 10, destination, FONT_STANDARD, &bmp_bottom_left_arrow,
        &bmp_bottom_right_arrow);
  } else if (index == 2) {
    layoutHeader(tx_msg[0]);
    char desc[11] = {0};
    strcat(desc, _("From"));
    strcat(desc, ":");
    oledDrawStringAdapter(0, y, desc, FONT_STANDARD);
    bubble_key = oledDrawPageableStringAdapter(
        0, y + 10, from_str, FONT_STANDARD, &bmp_bottom_left_arrow,
        &bmp_bottom_right_arrow);
  } else if (index == 3) {
    layoutHeader(tx_msg[0]);
    char desc[11] = {0};
    strcat(desc, _("Fee"));
    strcat(desc, ":");
    oledDrawStringAdapter(0, y, desc, FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, fee_str, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);

  } else if (max_index == index) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, 13, tx_msg[1], FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  } else if (index == 4) {
    char payment_id_hex[65];
    data2hex(msg->payment_id.bytes, 32, payment_id_hex);
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, 13, "Payment ID:", FONT_STANDARD);
    bubble_key = oledDrawPageableStringAdapter(
        0, y + 10, payment_id_hex, FONT_STANDARD, &bmp_bottom_left_arrow,
        &bmp_bottom_right_arrow);
  }
  oledRefresh();
  HANDLE_KEY(bubble_key);
}
void generate_ring_signature(const uint8_t* prefix_hash,
                             const ge25519* key_image, uint8_t n,
                             const ge25519 pubs[n], const bignum256modm sec_key,
                             uint8_t sec_idx, bignum256modm sigs[n][2]) {
  size_t buffer_offset = 32;
  uint8_t buffer[buffer_offset + 2 * 32 * n];
  memzero(buffer, sizeof(buffer));
  memcpy(buffer, prefix_hash, buffer_offset);
  bignum256modm sum = {0};
  bignum256modm k = {0};

  for (size_t i = 0; i < n; i++) {
    if (i == sec_idx) {
      xmr_random_scalar(k);
      ge25519 tmp2, tmp3 = {0};
      ge25519_set_neutral(&tmp2);
      ge25519_set_neutral(&tmp3);
      ge25519_scalarmult_base_wrapper(&tmp3, k);
      encodepoint(buffer + buffer_offset, &tmp3);
      buffer_offset += 32;
      uint8_t pub_bytes[32] = {0};
      encodepoint(pub_bytes, &pubs[i]);
      xmr_hash_to_ec(&tmp3, pub_bytes, sizeof(pub_bytes));
      ge25519_scalarmult(&tmp2, &tmp3, k);
      encodepoint(buffer + buffer_offset, &tmp2);
      buffer_offset += 32;
    } else {
      xmr_random_scalar(sigs[i][0]);
      xmr_random_scalar(sigs[i][1]);
      ge25519 tmp2, tmp3 = {0};
      ge25519_set_neutral(&tmp2);
      ge25519_set_neutral(&tmp3);
      tmp3 = pubs[i];
      ge25519_double_scalarmult_vartime(&tmp2, &tmp3, sigs[i][0], sigs[i][1]);
      encodepoint(buffer + buffer_offset, &tmp2);
      buffer_offset += 32;
      uint8_t tmp3_bytes[32] = {0};
      encodepoint(tmp3_bytes, &tmp3);
      xmr_hash_to_ec(&tmp3, tmp3_bytes, sizeof(tmp3_bytes));
      xmr_add_keys3_vartime(&tmp2, sigs[i][1], &tmp3, sigs[i][0], key_image);
      buffer_offset += 32;
      add256_modm(sum, sum, sigs[i][0]);
    }
  }
  bignum256modm h = {0};
  xmr_hash_to_scalar(h, buffer, sizeof(buffer));
  sub256_modm(sigs[sec_idx][0], h, sum);
  mulsub256_modm(sigs[sec_idx][1], sigs[sec_idx][0], sec_key, k);
}
