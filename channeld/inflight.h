#ifndef CHANNELD_INFLIGHT
#define CHANNELD_INFLIGHT

#include <bitcoin/tx.h>
#include <common/amount.h>

struct inflight {
	struct bitcoin_outpoint outpoint;
	struct amount_sat amnt;
};

#endif /* CHANNELD_INFLIGHT */
