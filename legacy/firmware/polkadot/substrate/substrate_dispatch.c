#include "substrate_dispatch.h"
#include "../parser_impl.h"

parser_error_t _readMethod(parser_context_t* c, uint8_t moduleIdx,
                           uint8_t callIdx, pd_Method_t* method) {
  // switch (c->tx_obj->transactionVersion) {
  // case 25:
  // case 2:
  //     return _readMethod_V25(c, moduleIdx, callIdx, &method->V25);
  // case 26:
  // case 9:
  //     return _readMethod_V26(c, moduleIdx, callIdx, &method->V26);
  // default:
  //     return parser_tx_version_not_supported;
  // }
  return _readMethod_V26(c, moduleIdx, callIdx, &method->V26);
}

uint8_t _getMethod_NumItems(uint32_t transactionVersion, uint8_t moduleIdx,
                            uint8_t callIdx) {
  // switch (transactionVersion) {
  // case 25:
  // case 2:
  //     return _getMethod_NumItems_V25(moduleIdx, callIdx);
  // case 26:
  // case 9:
  //     return _getMethod_NumItems_V26(moduleIdx, callIdx);
  // default:
  //     return 0;
  // }
  (void)transactionVersion;
  return _getMethod_NumItems_V26(moduleIdx, callIdx);
}

const char* _getMethod_ModuleName(uint32_t transactionVersion,
                                  uint8_t moduleIdx) {
  // switch (transactionVersion) {
  // case 25:
  // case 2:
  //     return _getMethod_ModuleName_V25(moduleIdx);
  // case 26:
  // case 9:
  //     return _getMethod_ModuleName_V26(moduleIdx);
  // default:
  //     return NULL;
  // }
  (void)transactionVersion;
  return _getMethod_ModuleName_V26(moduleIdx);
}

const char* _getMethod_Name(uint32_t transactionVersion, uint8_t moduleIdx,
                            uint8_t callIdx) {
  // switch (transactionVersion) {
  // case 25:
  // case 2:
  //     return _getMethod_Name_V25(moduleIdx, callIdx);
  // case 26:
  // case 9:
  //     return _getMethod_Name_V26(moduleIdx, callIdx);
  // default:
  //     return NULL;
  // }
  (void)transactionVersion;
  return _getMethod_Name_V26(moduleIdx, callIdx);
}

const char* _getMethod_ItemName(uint32_t transactionVersion, uint8_t moduleIdx,
                                uint8_t callIdx, uint8_t itemIdx) {
  // switch (transactionVersion) {
  // case 25:
  // case 2:
  //     return _getMethod_ItemName_V25(moduleIdx, callIdx, itemIdx);
  // case 26:
  // case 9:
  //     return _getMethod_ItemName_V26(moduleIdx, callIdx, itemIdx);
  // default:
  //     return NULL;
  // }
  (void)transactionVersion;
  return _getMethod_ItemName_V26(moduleIdx, callIdx, itemIdx);
}

parser_error_t _getMethod_ItemValue(uint32_t transactionVersion, pd_Method_t* m,
                                    uint8_t moduleIdx, uint8_t callIdx,
                                    uint8_t itemIdx, char* outValue,
                                    uint16_t outValueLen, uint8_t pageIdx,
                                    uint8_t* pageCount) {
  // switch (transactionVersion) {
  // case 25:
  // case 2:
  //     return _getMethod_ItemValue_V25(&m->V25, moduleIdx, callIdx, itemIdx,
  //     outValue,
  //         outValueLen, pageIdx, pageCount);
  // case 26:
  // case 9:
  //     return _getMethod_ItemValue_V26(&m->V26, moduleIdx, callIdx, itemIdx,
  //     outValue,
  //         outValueLen, pageIdx, pageCount);
  // default:
  //     return parser_tx_version_not_supported;
  // }
  (void)transactionVersion;
  return _getMethod_ItemValue_V26(&m->V26, moduleIdx, callIdx, itemIdx,
                                  outValue, outValueLen, pageIdx, pageCount);
}

bool _getMethod_ItemIsExpert(uint32_t transactionVersion, uint8_t moduleIdx,
                             uint8_t callIdx, uint8_t itemIdx) {
  // switch (transactionVersion) {
  // case 25:
  // case 2:
  //     return _getMethod_ItemIsExpert_V25(moduleIdx, callIdx, itemIdx);
  // case 26:
  // case 9:
  //     return _getMethod_ItemIsExpert_V26(moduleIdx, callIdx, itemIdx);
  // default:
  //     return false;
  // }
  (void)transactionVersion;
  return _getMethod_ItemIsExpert_V26(moduleIdx, callIdx, itemIdx);
}

bool _getMethod_IsNestingSupported(uint32_t transactionVersion,
                                   uint8_t moduleIdx, uint8_t callIdx) {
  // switch (transactionVersion) {
  // case 25:
  // case 2:
  //     return _getMethod_IsNestingSupported_V25(moduleIdx, callIdx);
  // case 26:
  // case 9:
  //     return _getMethod_IsNestingSupported_V26(moduleIdx, callIdx);
  // default:
  //     return false;
  // }
  (void)transactionVersion;
  return _getMethod_IsNestingSupported_V26(moduleIdx, callIdx);
}
