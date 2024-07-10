#include "substrate_dispatch_V25.h"
#include <stdint.h>
#include "../common_defs.h"
#include "substrate_strings.h"
#include "substrate_types.h"
extern char polkadot_network[32];

__Z_INLINE parser_error_t _readMethod_balances_transfer_allow_death_V25(
    parser_context_t* c, pd_balances_transfer_allow_death_V25_t* m) {
  CHECK_ERROR(_readAccountIdLookupOfT(c, &m->dest))
  CHECK_ERROR(_readCompactBalance(c, &m->amount))
  return parser_ok;
}

__Z_INLINE parser_error_t _readMethod_balances_force_transfer_V25(
    parser_context_t* c, pd_balances_force_transfer_V25_t* m) {
  CHECK_ERROR(_readAccountIdLookupOfT(c, &m->source))
  CHECK_ERROR(_readAccountIdLookupOfT(c, &m->dest))
  CHECK_ERROR(_readCompactBalance(c, &m->amount))
  return parser_ok;
}

__Z_INLINE parser_error_t _readMethod_balances_transfer_keep_alive_V25(
    parser_context_t* c, pd_balances_transfer_keep_alive_V25_t* m) {
  CHECK_ERROR(_readAccountIdLookupOfT(c, &m->dest))
  CHECK_ERROR(_readCompactBalance(c, &m->amount))
  return parser_ok;
}

__Z_INLINE parser_error_t _readMethod_balances_transfer_all_V25(
    parser_context_t* c, pd_balances_transfer_all_V25_t* m) {
  CHECK_ERROR(_readAccountIdLookupOfT(c, &m->dest))
  CHECK_ERROR(_readbool(c, &m->keep_alive))
  return parser_ok;
}
parser_error_t _readMethod_V25(parser_context_t* c, uint8_t moduleIdx,
                               uint8_t callIdx, pd_Method_V25_t* method) {
  uint16_t callPrivIdx = ((uint16_t)moduleIdx << 8u) + callIdx;

  switch (callPrivIdx) {
    // Kusama, westend
    case 1024: /* module 4 call 0 */  // kusama, westend
    case 1031:  // TODO: Check if this is correct ?? Kusama only
    case 1280: /* module 5 call 0 */  // Polkadot/ joystream
    case 1287:  // TODO: Check if this is correct ?? Polkadot only
    case 2560: /* module 5 call 0 */   // Manta
    case 7936: /* module 31 call 0 */  // Astar
    case 7943: /* module 31 call 0 */  // Astar
      CHECK_ERROR(_readMethod_balances_transfer_allow_death_V25(
          c, &method->nested.balances_transfer_allow_death_V25))
      break;
    case 1026: /* module 4 call 2 */   // kusama, westend
    case 1282: /* module 5 call 2 */   // Polkadot only
    case 2562: /* module 5 call 2 */   // Manta
    case 7938: /* module 31 call 2 */  // Astar
      CHECK_ERROR(_readMethod_balances_force_transfer_V25(
          c, &method->nested.balances_force_transfer_V25))
      break;
    case 1027: /* module 4 call 3 */   // kusama, westend
    case 1283: /* module 5 call 3 */   // Polkadot/ joystream
    case 2563: /* module 5 call 3 */   // Manta
    case 7939: /* module 31 call 3 */  // Astar
      CHECK_ERROR(_readMethod_balances_transfer_keep_alive_V25(
          c, &method->nested.balances_transfer_keep_alive_V25))
      break;
    case 1028: /* module 4 call 4 */   // kusama, westend
    case 1284: /* module 5 call 4 */   // Polkadot/ joystream
    case 2564: /* module 5 call 4 */   // Manta
    case 7940: /* module 31 call 4 */  // Astar
      CHECK_ERROR(_readMethod_balances_transfer_all_V25(
          c, &method->nested.balances_transfer_all_V25))
      break;

    default:
      return parser_unexpected_callIndex;
  }

  return parser_ok;
}

const char* _getMethod_ModuleName_V25(uint8_t moduleIdx) {
  switch (moduleIdx) {
    case 4:  // Kusama / Westend
    case 5:  // Polkadot / Joystream / Manta
    // case 10: // todo: check if this is correct
    case 31:  // Astar
      return STR_MO_BALANCES;
    default:
      return NULL;
  }

  return NULL;
}

const char* _getMethod_Name_V25(uint8_t moduleIdx, uint8_t callIdx) {
  uint16_t callPrivIdx = ((uint16_t)moduleIdx << 8u) + callIdx;

  switch (callPrivIdx) {
    case 1024:
    case 1031:
    case 1280: /* module 5 call 0 */
    case 1287:
    case 2560:
    case 7936:
    case 7943:
      return STR_ME_TRANSFER_ALLOW_DEATH;
    case 1026:
    case 1282: /* module 5 call 2 */
    case 2562:
    case 7938:
      return STR_ME_FORCE_TRANSFER;
    case 1027:
    case 1283: /* module 5 call 3 */
    case 2563:
    case 7939:
      return STR_ME_TRANSFER_KEEP_ALIVE;
    case 1028:
    case 1284: /* module 5 call 4 */
    case 2564:
    case 7940:
      return STR_ME_TRANSFER_ALL;
    default:
      return NULL;
  }
  return NULL;
}

uint8_t _getMethod_NumItems_V25(uint8_t moduleIdx, uint8_t callIdx) {
  uint16_t callPrivIdx = ((uint16_t)moduleIdx << 8u) + callIdx;

  switch (callPrivIdx) {
    case 1024:
    case 1031:
    case 1280: /* module 5 call 0 */
    case 1287:
    case 2560:
    case 7936:
    case 7943:
      return 2;
    case 1026:
    case 1282: /* module 5 call 2 */
    case 2562:
    case 7938:
      return 3;
    case 1027:
    case 1283: /* module 5 call 3 */
    case 2563:
    case 7939:
      return 2;
    case 1028:
    case 1284: /* module 5 call 4 */
    case 2564:
    case 7940:
      return 2;
    default:
      return 0;
  }
  return 0;
}

const char* _getMethod_ItemName_V25(uint8_t moduleIdx, uint8_t callIdx,
                                    uint8_t itemIdx) {
  uint16_t callPrivIdx = ((uint16_t)moduleIdx << 8u) + callIdx;

  switch (callPrivIdx) {
    case 1024:
    case 1031:
    case 1280: /* module 5 call 0 */
    case 1287:
    case 2560:
    case 7936:
    case 7943:
      switch (itemIdx) {
        case 0:
          return STR_IT_AMOUNT;
        case 1:
          return STR_IT_DEST;
      }
      break;
    case 1026:
    case 1282: /* module 5 call 2 */
    case 2562:
    case 7938:
      switch (itemIdx) {
        case 0:
          return STR_IT_AMOUNT;
        case 1:
          return STR_IT_SOURCE;
        case 2:
          return STR_IT_DEST;
      }
      break;
    case 1027:
    case 1283: /* module 5 call 3 */
    case 2563:
    case 7939:
      switch (itemIdx) {
        case 0:
          return STR_IT_AMOUNT;
        case 1:
          return STR_IT_DEST;
      }
      break;
    case 1028:
    case 1284: /* module 5 call 4 */
    case 2564:
    case 7940:
      switch (itemIdx) {
        case 0:
          return STR_IT_DEST;
        case 1:
          return STR_IT_KEEP_ALIVE;
      }
      break;
  }
  return NULL;
}

parser_error_t _getMethod_ItemValue_V25(pd_Method_V25_t* m, uint8_t moduleIdx,
                                        uint8_t callIdx, uint8_t itemIdx,
                                        char* outValue, uint16_t outValueLen,
                                        uint8_t pageIdx, uint8_t* pageCount) {
  uint16_t callPrivIdx = ((uint16_t)moduleIdx << 8u) + callIdx;

  switch (callPrivIdx) {
    case 1024:
    case 1031:
    case 1280: /* module 5 call 0 */
    case 1287:
    case 2560:
    case 7936:
    case 7943:
      switch (itemIdx) {
        case 0:
          return _toStringCompactBalance(
              &m->nested.balances_transfer_allow_death_V25.amount, outValue,
              outValueLen, pageIdx, pageCount);
        case 1:
          return _toStringAccountIdLookupOfT(
              &m->nested.balances_transfer_allow_death_V25.dest, outValue,
              outValueLen, pageIdx, pageCount);
        default:
          return parser_no_data;
      }
      break;
    case 1026:
    case 1282: /* module 5 call 2 */
    case 2562:
    case 7938:
      switch (itemIdx) {
        case 0:
          return _toStringCompactBalance(
              &m->nested.balances_force_transfer_V25.amount, outValue,
              outValueLen, pageIdx, pageCount);
        case 1:
          return _toStringAccountIdLookupOfT(
              &m->nested.balances_force_transfer_V25.source, outValue,
              outValueLen, pageIdx, pageCount);
        case 2:
          return _toStringAccountIdLookupOfT(
              &m->nested.balances_force_transfer_V25.dest, outValue,
              outValueLen, pageIdx, pageCount);
        default:
          return parser_no_data;
      }
      break;
    case 1027:
    case 1283: /* module 5 call 3 */
    case 2563:
    case 7939:
      switch (itemIdx) {
        case 0:
          return _toStringCompactBalance(
              &m->nested.balances_transfer_keep_alive_V25.amount, outValue,
              outValueLen, pageIdx, pageCount);
        case 1:
          return _toStringAccountIdLookupOfT(
              &m->nested.balances_transfer_keep_alive_V25.dest, outValue,
              outValueLen, pageIdx, pageCount);
        default:
          return parser_no_data;
      }
      break;
    case 1028:
    case 1284: /* module 5 call 4 */
    case 2564:
    case 7940:
      switch (itemIdx) {
        case 0:
          return _toStringAccountIdLookupOfT(
              &m->nested.balances_transfer_all_V25.dest, outValue, outValueLen,
              pageIdx, pageCount);
        case 1:
          return _toStringbool(&m->nested.balances_transfer_all_V25.keep_alive,
                               outValue, outValueLen, pageCount);
        default:
          return parser_no_data;
      }
      break;
    default:
      return parser_ok;
  }
  return parser_ok;
}
bool _getMethod_ItemIsExpert_V25(uint8_t moduleIdx, uint8_t callIdx,
                                 uint8_t itemIdx) {
  (void)moduleIdx;
  (void)callIdx;
  (void)itemIdx;
  return false;
}

bool _getMethod_IsNestingSupported_V25(uint8_t moduleIdx, uint8_t callIdx) {
  uint16_t callPrivIdx = ((uint16_t)moduleIdx << 8u) + callIdx;
  switch (callPrivIdx) {
    case 1024:
    case 1031:
    case 1280:
    case 1287:
    case 2560:
    case 7936:
    case 7943:
    case 1026:
    case 1282:
    case 2562:
    case 7938:
    case 1027:
    case 1283:
    case 2563:
    case 7939:
    case 1028:
    case 1284:
    case 2564:
    case 7940:
      return true;
    default:
      return false;
  }
}
