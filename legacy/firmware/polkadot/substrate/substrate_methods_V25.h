#include "substrate_types.h"

#define PD_CALL_SYSTEM_V25 0
#define PD_CALL_TIMESTAMP_V25 2
#define PD_CALL_INDICES_V25 3
#define PD_CALL_BALANCES_V25 4
#define PD_CALL_STAKING_V25 6
#define PD_CALL_SESSION_V25 8
#define PD_CALL_TREASURY_V25 18

#define PD_CALL_BALANCES_TRANSFER_ALLOW_DEATH_V25 0
typedef struct {
  pd_AccountIdLookupOfT_t dest;
  pd_CompactBalance_t amount;
} pd_balances_transfer_allow_death_V25_t;

#define PD_CALL_BALANCES_FORCE_TRANSFER_V25 2
typedef struct {
  pd_AccountIdLookupOfT_t source;
  pd_AccountIdLookupOfT_t dest;
  pd_CompactBalance_t amount;
} pd_balances_force_transfer_V25_t;

#define PD_CALL_BALANCES_TRANSFER_KEEP_ALIVE_V25 3
typedef struct {
  pd_AccountIdLookupOfT_t dest;
  pd_CompactBalance_t amount;
} pd_balances_transfer_keep_alive_V25_t;

#define PD_CALL_BALANCES_TRANSFER_ALL_V25 4
typedef struct {
  pd_AccountIdLookupOfT_t dest;
  pd_bool_t keep_alive;
} pd_balances_transfer_all_V25_t;

typedef union {
  pd_balances_transfer_allow_death_V25_t balances_transfer_allow_death_V25;
  pd_balances_force_transfer_V25_t balances_force_transfer_V25;
  pd_balances_transfer_keep_alive_V25_t balances_transfer_keep_alive_V25;
  pd_balances_transfer_all_V25_t balances_transfer_all_V25;
} pd_MethodNested_V25_t;

typedef union {
  // pd_MethodBasic_V25_t basic;
  pd_MethodNested_V25_t nested;
} pd_Method_V25_t;
