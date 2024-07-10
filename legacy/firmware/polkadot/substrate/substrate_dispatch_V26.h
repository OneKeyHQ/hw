#ifndef __POLKADOT_SUBSTRATE_DISPATCH_V26_H__
#define __POLKADOT_SUBSTRATE_DISPATCH_V26_H__

#include <stddef.h>
#include <stdint.h>
#include "../parser_impl.h"
#include "stdbool.h"
#include "substrate_functions.h"
#include "substrate_functions_V26.h"

parser_error_t _readMethod_V26(parser_context_t* c, uint8_t moduleIdx,
                               uint8_t callIdx, pd_Method_V26_t* method);

const char* _getMethod_ModuleName_V26(uint8_t moduleIdx);

const char* _getMethod_Name_V26(uint8_t moduleIdx, uint8_t callIdx);
const char* _getMethod_Name_V26_ParserFull(uint16_t callPrivIdx);

const char* _getMethod_ItemName_V26(uint8_t moduleIdx, uint8_t callIdx,
                                    uint8_t itemIdx);

uint8_t _getMethod_NumItems_V26(uint8_t moduleIdx, uint8_t callIdx);

parser_error_t _getMethod_ItemValue_V26(pd_Method_V26_t* m, uint8_t moduleIdx,
                                        uint8_t callIdx, uint8_t itemIdx,
                                        char* outValue, uint16_t outValueLen,
                                        uint8_t pageIdx, uint8_t* pageCount);

bool _getMethod_ItemIsExpert_V26(uint8_t moduleIdx, uint8_t callIdx,
                                 uint8_t itemIdx);
bool _getMethod_IsNestingSupported_V26(uint8_t moduleIdx, uint8_t callIdx);

#endif
