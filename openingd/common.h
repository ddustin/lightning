#ifndef LIGHTNING_OPENINGD_COMMON_H
#define LIGHTNING_OPENINGD_COMMON_H

#include "config.h"

struct amount_sat;
struct bip340sig;
struct bitcoin_tx;
struct bitcoin_signature;
struct channel_config;

bool check_eltoo_config_bounds(const tal_t *ctx,
             struct amount_sat funding,
             u32 max_shared_delay,
             struct amount_msat min_effective_htlc_capacity,
             const struct eltoo_channel_config *remoteconf,
             const struct eltoo_channel_config *localconf,
             char **err_reason);

bool check_config_bounds(const tal_t *ctx,
			 struct amount_sat funding,
			 u32 feerate_per_kw,
			 u32 max_to_self_delay,
			 struct amount_msat min_effective_htlc_capacity,
			 const struct channel_config *remoteconf,
			 const struct channel_config *localconf,
			 bool am_opener,
			 bool option_anchor_outputs,
			 char **err_reason);

u8 *no_upfront_shutdown_script(const tal_t *ctx,
			       struct feature_set *our_features,
			       const u8 *their_features);

void validate_initial_commitment_signature(int hsm_fd,
					   struct bitcoin_tx *tx,
					   struct bitcoin_signature *sig);

void validate_initial_update_psig(int hsm_fd,
                       struct channel_id *channel_id,
                       struct bitcoin_tx *update_tx,
                       struct partial_sig *p_sig);
#endif /* LIGHTNING_OPENINGD_COMMON_H */
