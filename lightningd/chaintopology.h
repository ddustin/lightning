#ifndef LIGHTNING_LIGHTNINGD_CHAINTOPOLOGY_H
#define LIGHTNING_LIGHTNINGD_CHAINTOPOLOGY_H
#include "config.h"
#include <bitcoin/block.h>
#include <ccan/list/list.h>
#include <lightningd/feerate.h>
#include <lightningd/watch.h>

struct bitcoin_tx;
struct bitcoind;
struct command;
struct lightningd;
struct peer;
struct txwatch;

/* We keep the last three in case there are outliers (for min/max) */
#define FEE_HISTORY_NUM 3

/* Off topology->outgoing_txs */
struct outgoing_tx {
	struct channel *channel;
	const struct bitcoin_tx *tx;
	struct bitcoin_txid txid;
	const char *cmd_id;
	void (*finished)(struct channel *channel, bool success, const char *err);
};

struct block {
	u32 height;

	/* Actual header. */
	struct bitcoin_block_hdr hdr;

	/* Previous block (if any). */
	struct block *prev;

	/* Next block (if any). */
	struct block *next;

	/* Key for hash table */
	struct bitcoin_blkid blkid;

	/* Full copy of txs (freed in filter_block_txs) */
	struct bitcoin_tx **full_txs;
	struct bitcoin_txid *txids;
};

/* Hash blocks by sha */
static inline const struct bitcoin_blkid *keyof_block_map(const struct block *b)
{
	return &b->blkid;
}

static inline size_t hash_sha(const struct bitcoin_blkid *key)
{
	size_t ret;

	memcpy(&ret, key, sizeof(ret));
	return ret;
}

static inline bool block_eq(const struct block *b, const struct bitcoin_blkid *key)
{
	return bitcoin_blkid_eq(&b->blkid, key);
}
HTABLE_DEFINE_TYPE(struct block, keyof_block_map, hash_sha, block_eq, block_map);

/* Hash blocks by sha */
static inline const struct bitcoin_txid *keyof_outgoing_tx_map(const struct outgoing_tx *t)
{
	return &t->txid;
}

static inline size_t outgoing_tx_hash_sha(const struct bitcoin_txid *key)
{
	size_t ret;
	memcpy(&ret, key, sizeof(ret));
	return ret;
}

static inline bool outgoing_tx_eq(const struct outgoing_tx *b, const struct bitcoin_txid *key)
{
	return bitcoin_txid_eq(&b->txid, key);
}
HTABLE_DEFINE_TYPE(struct outgoing_tx, keyof_outgoing_tx_map,
		   outgoing_tx_hash_sha, outgoing_tx_eq, outgoing_tx_map);

struct chain_topology {
	struct lightningd *ld;
	struct block *root;
	struct block *tip;
	struct bitcoin_blkid prev_tip;
	struct block_map *block_map;
	u32 feerate[NUM_FEERATES];
	bool feerate_uninitialized;
	u32 feehistory[NUM_FEERATES][FEE_HISTORY_NUM];

	/* Where to log things. */
	struct log *log;

	/* What range of blocks do we have in our database? */
	u32 min_blockheight, max_blockheight;

	/* How often to poll. */
	u32 poll_seconds;

	/* struct sync_waiters waiting for us to catch up with bitcoind (and
	 * once that has caught up with the network).  NULL if we're already
	 * caught up. */
	struct list_head *sync_waiters;

	/* The bitcoind. */
	struct bitcoind *bitcoind;

	/* Timers we're running. */
	struct oneshot *extend_timer, *updatefee_timer;

	/* Bitcoin transactions we're broadcasting */
	struct outgoing_tx_map *outgoing_txs;

	/* Transactions/txos we are watching. */
	struct txwatch_hash *txwatches;
	struct txowatch_hash *txowatches;

	/* The number of headers known to the bitcoin backend at startup. Not
	 * updated after the initial check. */
	u32 headercount;

	/* Are we stopped? */
	bool stopping;
};

/* Information relevant to locating a TX in a blockchain. */
struct txlocator {

	/* The height of the block that includes this transaction */
	u32 blkheight;

	/* Position of the transaction in the transactions list */
	u32 index;
};

/* This is the number of blocks which would have to be mined to invalidate
 * the tx */
size_t get_tx_depth(const struct chain_topology *topo,
		    const struct bitcoin_txid *txid);

/* Get highest block number. */
u32 get_block_height(const struct chain_topology *topo);

/* Get the highest block number in the network that we are aware of. Unlike
 * `get_block_height` this takes into consideration the block header counter
 * in the bitcoin backend as well. If an absolute time is required, rather
 * than our current scan position this is preferable since it is far less
 * likely to lag behind the rest of the network.*/
u32 get_network_blockheight(const struct chain_topology *topo);

/* Get fee rate in satoshi per kiloweight, or 0 if unavailable! */
u32 try_get_feerate(const struct chain_topology *topo, enum feerate feerate);

/* Get range of feerates to insist other side abide by for normal channels.
 * If we have to guess, sets *unknown to true, otherwise false. */
u32 feerate_min(struct lightningd *ld, bool *unknown);
u32 feerate_max(struct lightningd *ld, bool *unknown);

u32 opening_feerate(struct chain_topology *topo);
u32 mutual_close_feerate(struct chain_topology *topo);
u32 unilateral_feerate(struct chain_topology *topo);
/* For onchain resolution. */
u32 delayed_to_us_feerate(struct chain_topology *topo);
u32 htlc_resolution_feerate(struct chain_topology *topo);
u32 penalty_feerate(struct chain_topology *topo);

/**
 * broadcast_tx - Broadcast a single tx, and rebroadcast as reqd (copies tx).
 * @topo: topology
 * @channel: the channel responsible for this (stop broadcasting if freed).
 * @tx: the transaction
 * @cmd_id: the JSON command id which triggered this (or NULL).
 * @allowhighfees: set to true to override the high-fee checks in the backend.
 * @finished: if non-NULL, call that and don't rebroadcast.
 */
void broadcast_tx(struct chain_topology *topo,
		  struct channel *channel,
		  const struct bitcoin_tx *tx TAKES,
		  const char *cmd_id, bool allowhighfees,
		  void (*finished)(struct channel *,
				   bool success,
				   const char *err));

struct chain_topology *new_topology(struct lightningd *ld, struct log *log);
void setup_topology(struct chain_topology *topology,
		    u32 min_blockheight, u32 max_blockheight);

void begin_topology(struct chain_topology *topo);

void stop_topology(struct chain_topology *topo);

struct txlocator *locate_tx(const void *ctx, const struct chain_topology *topo, const struct bitcoin_txid *txid);

static inline bool topology_synced(const struct chain_topology *topo)
{
	return topo->sync_waiters == NULL;
}

/**
 * topology_add_sync_waiter: wait for lightningd to sync with bitcoin network
 * @ctx: context to allocate the waiter from.
 * @topo: chain topology
 * @cb: callback to call when we're synced.
 * @arg: arg for @cb
 *
 * topology_synced() must be false when this is called.  It will be true
 * when @cb is called.  @cb will not be called if @ctx is freed first.
 */
void topology_add_sync_waiter_(const tal_t *ctx,
			       struct chain_topology *topo,
			       void (*cb)(struct chain_topology *,
					  void *),
			       void *arg);
#define topology_add_sync_waiter(ctx, topo, cb, arg)			\
	topology_add_sync_waiter_((ctx), (topo),			\
				  typesafe_cb_preargs(void, void *,	\
						      (cb), (arg),	\
						      struct chain_topology *), \
				  (arg))


/* In channel_control.c */
void notify_feerate_change(struct lightningd *ld);
#endif /* LIGHTNING_LIGHTNINGD_CHAINTOPOLOGY_H */
