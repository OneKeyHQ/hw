#include "ton_tokens.h"
#include <string.h>

#define TON_TOKENS_COUNT 2
const TonTokenType ton_tokens[TON_TOKENS_COUNT + 1] = {
    {"EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs", " USDT", 6},
    {"EQAvlWFDxGF2lXm67y4yzC17wYKD9A0guwPkMs1gOsM__NOT", " NOT", 9},
    {"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", " UNKN", 0},
};

ConstTonTokenPtr ton_get_token_by_address(const char *address) {
  for (int i = 0; i < TON_TOKENS_COUNT; i++) {
    if (memcmp(address, ton_tokens[i].address, 48) != 0) continue;
    return &ton_tokens[i];
  }

  return &ton_tokens[TON_TOKENS_COUNT];  // UNKN TOKEN
}
