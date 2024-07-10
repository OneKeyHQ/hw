#include "substrate_types.h"

#define PD_CALL_SYSTEM_V26 0
#define PD_CALL_BALANCES_V26 4
#define PD_CALL_STAKING_V26 6
#define PD_CALL_SESSION_V26 8
#define PD_CALL_TREASURY_V26 18

#define PD_CALL_UTILITY_BATCH_V26 0
typedef struct {
  pd_VecCall_t calls;
} pd_utility_batch_V26_t;

#define PD_CALL_UTILITY_BATCH_ALL_V26 2
typedef struct {
  pd_VecCall_t calls;
} pd_utility_batch_all_V26_t;

#define PD_CALL_UTILITY_FORCE_BATCH_V26 4
typedef struct {
  pd_VecCall_t calls;
} pd_utility_force_batch_V26_t;

typedef union {
  pd_utility_batch_V26_t utility_batch_V26;
  pd_utility_batch_all_V26_t utility_batch_all_V26;
  pd_utility_force_batch_V26_t utility_force_batch_V26;
} pd_MethodBasic_V26_t;

#define PD_CALL_BALANCES_TRANSFER_ALLOW_DEATH_V26 0
typedef struct {
  pd_AccountIdLookupOfT_t dest;
  pd_CompactBalance_t amount;
} pd_balances_transfer_allow_death_V26_t;

#define PD_CALL_BALANCES_FORCE_TRANSFER_V26 2
typedef struct {
  pd_AccountIdLookupOfT_t source;
  pd_AccountIdLookupOfT_t dest;
  pd_CompactBalance_t amount;
} pd_balances_force_transfer_V26_t;

#define PD_CALL_BALANCES_TRANSFER_KEEP_ALIVE_V26 3
typedef struct {
  pd_AccountIdLookupOfT_t dest;
  pd_CompactBalance_t amount;
} pd_balances_transfer_keep_alive_V26_t;

#define PD_CALL_BALANCES_TRANSFER_ALL_V26 4
typedef struct {
  pd_AccountIdLookupOfT_t dest;
  pd_bool_t keep_alive;
} pd_balances_transfer_all_V26_t;

typedef union {
  pd_balances_transfer_allow_death_V26_t balances_transfer_allow_death_V26;
  pd_balances_force_transfer_V26_t balances_force_transfer_V26;
  pd_balances_transfer_keep_alive_V26_t balances_transfer_keep_alive_V26;
  pd_balances_transfer_all_V26_t balances_transfer_all_V26;
} pd_MethodNested_V26_t;

typedef union {
  pd_MethodBasic_V26_t basic;
  pd_MethodNested_V26_t nested;
} pd_Method_V26_t;
