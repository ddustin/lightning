from fixtures import *  # noqa: F401,F403
import pytest
import time


@pytest.mark.openchannel('v2')
def test_splice(node_factory, bitcoind):
    l1 = node_factory.get_node()
    l2 = node_factory.get_node()

    chan_size = 4000000

    l1.rpc.connect(l2.rpc.getinfo()['id'], 'localhost:%d' % l2.port)
    l1.openchannel(l2, chan_size)

    l2.daemon.wait_for_log(r'to CHANNELD_NORMAL')
    l1.daemon.wait_for_log(r'to CHANNELD_NORMAL')

    time.sleep(1)

    chan_id = l1.get_channel_id(l2)

    # add extra sats to pay fee
    funds_result = l1.rpc.fundpsbt("105000sat", "slow", 166, excess_as_change=True)

    chan_size += 100000

    result = l1.rpc.splice_init(chan_id, chan_size, funds_result['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    result = l1.rpc.signpsbt(result['psbt'])
    result = l1.rpc.splice_signed(chan_id, result['signed_psbt'])

    bitcoind.generate_block(6, wait_for_mempool=1)

    l2.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l1.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')

    inv = l2.rpc.invoice(10**2, '3', 'no_3')
    l1.rpc.pay(inv['bolt11'])

    result = True
