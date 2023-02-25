CREATE TABLE htlc_sigs
(
        channelid INTEGER REFERENCES channels(id) ON DELETE CASCADE,
  NEW   inflight_id BLOB REFERENCES channel_funding_inflights(funding_tx_id), 
        signature BLOB
);

/* on splice +6 blocks: delete all NULL inflight_id values, change successful
 * splice candidate inflight_id's to NULL */

CREATE INDEX channel_idx ON htlc_sigs (channelid)

CREATE TABLE channel_funding_inflights (
           channel_id BIGSERIAL REFERENCES channels(id) ON DELETE CASCADE,
           funding_tx_id BLOB,
           funding_tx_outnum INTEGER,
           funding_feerate INTEGER,
           funding_satoshi BIGINT,
           our_funding_satoshi BIGINT,
           funding_psbt BLOB,
           last_tx BLOB,
           last_sig BLOB,
           funding_tx_remote_sigs_received INTEGER,

           lease_commit_sig BLOB DEFAULT NULL
           lease_chan_max_msat BIGINT DEFAULT NULL
           lease_chan_max_ppt INTEGER DEFAULT NULL
           lease_expiry INTEGER DEFAULT 0
           lease_blockheight_start INTEGER DEFAULT 0
           lease_fee BIGINT DEFAULT 0

  NEW      starting_htlc_id INTEGER DEFAULT 0,
           PRIMARY KEY (channel_id, funding_tx_id)
)

/* on splice +6 blocks: delete all htlcs with channel_id below starting_htlc_id */

CREATE TABLE channel_htlcs (
           id BIGSERIAL,
           channel_id BIGINT REFERENCES channels(id) ON DELETE CASCADE,
           channel_htlc_id BIGINT,
           direction INTEGER,
           origin_htlc BIGINT,
           msatoshi BIGINT,
           cltv_expiry INTEGER,
           payment_hash BLOB,
           payment_key BLOB,
           routing_onion BLOB,
           failuremsg BLOB, /* Note: This is in fact the failure onionreply
                                but renaming columns is hard! */
           malformed_onion INTEGER,
           hstate INTEGER,
           shared_secret BLOB,
           PRIMARY KEY (id),
           UNIQUE (channel_id, channel_htlc_id, direction)
)

CREATE UNIQUE INDEX channel_funding_inflights_channel_id
        ON channel_funding_inflights(funding_tx_id)


