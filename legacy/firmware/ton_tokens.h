#ifndef __TON_TOKENS_H__
#define __TON_TOKENS_H__

#include <stdint.h>

typedef struct {
  char address[49];  // tron address
  char name[10];   // token name
  int decimals;      // token decimals
} TonTokenType;

typedef const TonTokenType *ConstTonTokenPtr;

ConstTonTokenPtr ton_get_token_by_address(const char *address);

#endif  // __TRON_TOKENS_H__
