from fixtures import *  # noqa: F401,F403
import os
import pytest
import unittest


@unittest.skipIf(os.environ.get("EXPERIMENTAL_SPLICING", '0') != '1', "Need experimental splicing turned on")
@pytest.mark.openchannel('v2')
def test_splice(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, fundamount=1000000, wait_for_announce=True)

    # get channel id
    chan_id = l1.get_channel_id(l2)


    channels = l1.rpc.listpeerchannels()['channels']
    original_scid = channels[0].get('short_channel_id')

    # add extra sats to pay fee
    funds_result = l1.rpc.fundpsbt("109000sat", "slow", 166, excess_as_change=True)

    result = l1.rpc.splice_init(chan_id, 100000, funds_result['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    result = l1.rpc.signpsbt(result['psbt'])
    result = l1.rpc.splice_signed(chan_id, result['signed_psbt'])

    l2.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')
    l1.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')

    mempool = bitcoind.rpc.getrawmempool(True)
    assert len(list(mempool.keys())) == 1
    assert result['txid'] in list(mempool.keys())

    bitcoind.generate_block(9, wait_for_mempool=1)

    l2.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l1.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')

    inv = l2.rpc.invoice(10**2, '3', 'no_3')
    l1.rpc.pay(inv['bolt11'])
    
    peer_channels = l1.rpc.listpeerchannels()['channels']
    assert len(peer_channels) > 0

    new_scid = peer_channels[0].get('short_channel_id')

    assert new_scid != original_scid
    all_channels = l1.rpc.listchannels()['channels']
    print("ALL CHANNELS: {}".format(all_channels))
    assert len(all_channels) > 0