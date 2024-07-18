#include <stdint.h>
#include <stdbool.h>

#ifndef __TON_BITS_H__
#define __TON_BITS_H__

#define CHAIN_LEN 1
#define HASH_LEN 32

typedef struct BitString_t {
    uint8_t data[128];
    uint16_t data_cursor;  // NOTE: In bits
} BitString_t;

void bitstring_init(BitString_t* self);
void bitstring_write_bit(BitString_t* self, int8_t v);
void bitstring_write_uint(BitString_t* self, uint64_t v, uint8_t bits);

void bitstring_write_coins(BitString_t* self, uint64_t v);
void bitstring_write_buffer(BitString_t* self, uint8_t* v, uint8_t length);

void bitstring_write_address(BitString_t* self, uint8_t chain, uint8_t* hash);
void bitstring_write_null_address(BitString_t* self);

void bitstring_final(BitString_t* self);

int32_t ton_base64_decode(const char* in, size_t in_len, uint8_t* out, size_t max_out_len);

#endif