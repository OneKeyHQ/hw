#include <string.h>  // explicit_bzero
#include <stdint.h>
#include <stdlib.h>

#include "ton_bits.h"




void bitstring_init(BitString_t* self) {
    self->data_cursor = 0;
    explicit_bzero(self->data, sizeof(self->data));
}

void bitstring_write_bit(BitString_t* self, int8_t v) {
    if (v > 0) {
        // this.#buffer[(n / 8) | 0] |= 1 << (7 - (n % 8));
        self->data[(self->data_cursor / 8) | 0] |= (1 << (7 - (self->data_cursor % 8)));
    } else {
        // this.#buffer[(n / 8) | 0] &= ~(1 << (7 - (n % 8)));
        self->data[(self->data_cursor / 8) | 0] &= ~(1 << (7 - (self->data_cursor % 8)));
    }
    self->data_cursor++;
}

void bitstring_write_uint(BitString_t* self, uint64_t v, uint8_t bits) {
    for (int i = 0; i < bits; i++) {
        int8_t b = (v >> (bits - i - 1)) & 0x01;
        bitstring_write_bit(self, b);
    }
}

void bitstring_write_coins(BitString_t* self, uint64_t v) {
    // Measure length
    uint8_t len = 0;
    uint64_t r = v;
    for (int i = 0; i < 8; i++) {
        if (r > 0) {
            len++;
            r = r >> 8;
        } else {
            break;
        }
    }

    // Write length
    bitstring_write_uint(self, len, 4);

    // Write remaining
    for (int i = 0; i < len; i++) {
        bitstring_write_uint(self, v >> ((len - i - 1) * 8), 8);
    }
}

void bitstring_write_buffer(BitString_t* self, uint8_t* v, uint8_t length) {
    for (int i = 0; i < length; i++) {
        bitstring_write_uint(self, v[i], 8);
    }
}

void bitstring_write_address(BitString_t* self, uint8_t chain, uint8_t* hash) {
    bitstring_write_uint(self, 2, 2);
    bitstring_write_uint(self, 0, 1);
    bitstring_write_uint(self, chain, CHAIN_LEN * 8);
    bitstring_write_buffer(self, hash, HASH_LEN);
}

void bitstring_write_null_address(BitString_t* self) {
    bitstring_write_uint(self, 0, 2);
}

void bitstring_final(BitString_t* self) {
    uint8_t padBytes = self->data_cursor % 8;
    if (padBytes > 0) {
        padBytes = 8 - padBytes;
        padBytes = padBytes - 1;
        bitstring_write_bit(self, 1);
        while (padBytes > 0) {
            padBytes = padBytes - 1;
            bitstring_write_bit(self, 0);
        }
    }
}

int32_t ton_base64_decode(const char* in, size_t in_len, uint8_t* out, size_t max_out_len) {
    int32_t success = 0;
    const uint32_t base64_index[256] = {
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 62U, 63U, 62U, 62U, 63U, 52U, 53U, 54U, 55U, 56U, 57U, 58U, 59U, 60U,
        61U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U, 9U, 10U, 11U,
        12U, 13U, 14U, 15U, 16U, 17U, 18U, 19U, 20U, 21U, 22U, 23U, 24U, 25U, 0U, 0U, 0U,
        0U, 63U, 0U, 26U, 27U, 28U, 29U, 30U, 31U, 32U, 33U, 34U, 35U, 36U, 37U, 38U, 39U,
        40U, 41U, 42U, 43U, 44U, 45U, 46U, 47U, 48U, 49U, 50U, 51U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U
    };
    const uint8_t* in_data_uchar = (const uint8_t*)in;
    bool pad_bool = (in_len > 0U) && (((in_len % 4U) != 0U) || (in_data_uchar[in_len - 1U] == (uint8_t)'='));
    uint32_t pad_uint = 0U;
    if (pad_bool) {
        pad_uint = 1U;
    }
    const size_t len = (((in_len + 3U) / 4U) - pad_uint) * 4U;
    const size_t out_len = ((len / 4U) * 3U) + pad_uint;

    if (out_len > max_out_len) {
        success = 1;
    }

    if (len == 0U) {
        success = 1;
    }

    if (success == 0) {
        size_t j = 0U;
        for (size_t i = 0U; i < len; i += 4U) {
            uint32_t n = (base64_index[in_data_uchar[i]] << 18U) | (base64_index[in_data_uchar[i + 1U]] << 12U) |
                         (base64_index[in_data_uchar[i + 2U]] << 6U) | (base64_index[in_data_uchar[i + 3U]]);
            out[j] = (uint8_t)(n >> 16U);
            ++j;
            out[j] = (uint8_t)((n >> 8U) & 0xFFU);
            ++j;
            out[j] = (uint8_t)(n & 0xFFU);
            ++j;
        }
        if (pad_bool) {
            uint32_t n = (base64_index[in_data_uchar[len]] << 18U) | (base64_index[in_data_uchar[len + 1U]] << 12U);
            out[out_len - 1U] = (uint8_t)(n >> 16U);

            if ((in_len > (len + 2U)) && (in_data_uchar[len + 2U] != (uint8_t)'=')) {
                if ((out_len + 1U) > max_out_len) {
                    success = 1;
                } else {
                    n |= base64_index[in_data_uchar[len + 2U]] << 6U;
                    out[out_len] = (uint8_t)((n >> 8U) & 0xFFU);
                }
            }
        }
    }

    return success;
}