#ifndef __POLKADOT_SUBSTRATE_METHODS_H__
#define __POLKADOT_SUBSTRATE_METHODS_H__

#include "substrate_methods_V25.h"
#include "substrate_methods_V26.h"

typedef union {
  pd_Method_V26_t V26;
  pd_Method_V25_t V25;
} pd_Method_t;

typedef union {
  pd_MethodNested_V26_t V26;
  pd_MethodNested_V25_t V25;
} pd_MethodNested_t;

#endif
