#!/bin/sh

## Short script to startup some local nodes with
## bitcoind, all running on regtest
## Makes it easier to test things out, by hand.

## Should be called by source since it sets aliases
##
##  First load this file up.
##
##  $ source contrib/startup_regtest.sh
##
##  Start up the nodeset
##
##  $ start_ln 3
##
##  Let's connect the nodes.
##
##  $ l2-cli getinfo | jq .id
##    "02b96b03e42d9126cb5228752c575c628ad09bdb7a138ec5142bbca21e244ddceb"
##  $ l2-cli getinfo | jq .binding[0].port
##    9090
##  $ l1-cli connect 02b96b03e42d9126cb5228752c575c628ad09bdb7a138ec5142bbca21e244ddceb@localhost:9090
##    {
##      "id" : "030b02fc3d043d2d47ae25a9306d98d2abb7fc9bee824e68b8ce75d6d8f09d5eb7"
##    }
##
##  When you're finished, clean up or stop
##
##  $ stop_ln  # stops the services, keeps the aliases
##

# Do the Right Thing if we're currently in top of srcdir.
if [ -z "$PATH_TO_LIGHTNING" ] && [ -x cli/lightning-cli ] && [ -x lightningd/lightningd ]; then
	PATH_TO_LIGHTNING=$(pwd)
fi

if [ -z "$PATH_TO_LIGHTNING" ]; then
	# Already installed maybe?  Prints
	# shellcheck disable=SC2039
	type lightning-cli || return
	# shellcheck disable=SC2039
	type lightningd || return
	LCLI=lightning-cli
	LIGHTNINGD=lightningd
else
	LCLI="$PATH_TO_LIGHTNING"/cli/lightning-cli
	LIGHTNINGD="$PATH_TO_LIGHTNING"/lightningd/lightningd
	# This mirrors "type" output above.
	echo lightning-cli is "$LCLI"
	echo lightningd is "$LIGHTNINGD"
fi

if [ -z "$PATH_TO_BITCOIN" ]; then
	if [ -d "$HOME/.bitcoin" ]; then
		PATH_TO_BITCOIN="$HOME/.bitcoin"
	elif [ -d "$HOME/Library/Application Support/Bitcoin/" ]; then
		PATH_TO_BITCOIN="$HOME/Library/Application Support/Bitcoin/"
	else
		echo "\$PATH_TO_BITCOIN not set to a .bitcoin dir?" >&2
		return
	fi
fi

start_nodes() {
	if [ -z "$1" ]; then
		node_count=2
	else
		node_count=$1
	fi
	if [ "$node_count" -gt 100 ]; then
		node_count=100
	fi
	if [ -z "$2" ]; then
		network=regtest
	else
		network=$2
	fi

	LN_NODES=$node_count

	for i in $(seq $node_count); do
		socket=$(( 7070 + i * 101))
		mkdir -p "/tmp/l$i-$network"
		# Node config
		cat <<- EOF > "/tmp/l$i-$network/config"
		network=$network
		log-level=debug
		log-file=/tmp/l$i-$network/log
		addr=localhost:$socket
		EOF

		# If we've configured to use developer, add dev options
		if $LIGHTNINGD --help | grep -q dev-fast-gossip; then
			cat <<- EOF >> "/tmp/l$i-$network/config"
			dev-fast-gossip
			experimental-dual-fund
			dev-bitcoind-poll=5
			funder-policy=match
			funder-policy-mod=100
			funder-min-their-funding=10000
			funder-per-channel-max=100000
			funder-fuzz-percent=0
			lease-fee-base-msat=2sat
			lease-fee-basis=50
			EOF
		fi


		# Start the lightning nodes
		test -f "/tmp/l$i-$network/lightningd-$network.pid" || \
			"$LIGHTNINGD" "--lightning-dir=/tmp/l$i-$network" "--dev-debugger=eltoo_onchaind" &
		# shellcheck disable=SC2139 disable=SC2086
		alias l$i-cli="$LCLI --lightning-dir=/tmp/l$i-$network"
		# shellcheck disable=SC2139 disable=SC2086
		alias l$i-log="less /tmp/l$i-$network/log"
	done

	# Give a hint.
	echo "Commands: "
	for i in $(seq $node_count); do
		echo "	l$i-cli, l$i-log,"
	done
}

start_ln() {
	# Start bitcoind in the background
	test -f "$PATH_TO_BITCOIN/regtest/bitcoind.pid" || \
		$(pwd)/../bitcoin/src/bitcoind -regtest -txindex -fallbackfee=0.00000253 -daemon -daemonwait -trueoutputs=1 -annexcarrier=1

	# Wait for it to start
	while ! bitcoin-cli -regtest ping 2> /tmp/null; do echo "awaiting bitcoind..." && sleep 1; done

	# Kick it out of initialblockdownload if necessary
	if bitcoin-cli -regtest getblockchaininfo | grep -q 'initialblockdownload.*true'; then
		# Modern bitcoind needs createwallet
		bitcoin-cli -regtest createwallet default >/dev/null 2>&1
		bitcoin-cli -regtest generatetoaddress 1 "$(bitcoin-cli -regtest getnewaddress)" > /dev/null
	fi
	alias bt-cli='bitcoin-cli -regtest'

	if [ -z "$1" ]; then
		nodes=2
	else
		nodes="$1"
	fi
	start_nodes "$nodes" regtest
	echo "	bt-cli, stop_ln"
}

onchain_ln() {
    # Test eltoo_onchaind handling
    l1addr=$(l1-cli newaddr | jq -r .bech32)
    l2id=$(l2-cli getinfo | jq -r .id)
    bt-cli loadwallet "default"
    btcaddr=$(bt-cli getnewaddress)
    bt-cli sendtoaddress $l1addr 1
    l1-cli connect $l2id@localhost:7272
    bt-cli generatetoaddress 6 $btcaddr
    sleep 5
    l1-cli fundchannel $l2id 10000 normal false
    bt-cli generatetoaddress 6 $btcaddr
    sleep 5
    FIRST_UPDATE_HEX=$(l1-cli listpeers | jq -r .peers[0].channels[0].last_update_tx )
    FIRST_SETTLE_HEX=$(l1-cli listpeers | jq -r .peers[0].channels[0].last_settle_tx )
    FIRST_UNBOUND_UPDATE_HEX=$(l1-cli listpeers | jq -r .peers[0].channels[0].unbound_update_tx )
    FIRST_UNBOUND_SETTLE_HEX=$(l1-cli listpeers | jq -r .peers[0].channels[0].unbound_settle_tx )
    invoice=$(l2-cli invoice 10000 hi "test" | jq -r .bolt11)
    l1-cli pay $invoice
    sleep 0.2

    # Should be bound to funding output!
    UPDATE_HEX=$(l1-cli listpeers | jq -r .peers[0].channels[0].last_update_tx )
    SETTLE_HEX=$(l1-cli listpeers | jq -r .peers[0].channels[0].last_settle_tx )
    txid=$(bt-cli decoderawtransaction $FIRST_UPDATE_HEX | jq -r .txid)
    bt-cli prioritisetransaction $txid 0 100000000
    bt-cli sendrawtransaction $FIRST_UPDATE_HEX
    bt-cli generatetoaddress 1 $btcaddr

    # Settle tx can be broadcast after shared_delay, onchaind should
    # be trying to spend the update tx output itself!
    bt-cli generatetoaddress 6 $btcaddr
    txid=$(bt-cli decoderawtransaction $SETTLE_HEX | jq -r .txid)
    bt-cli prioritisetransaction $txid 0 100000000
    bt-cli sendrawtransaction $FIRST_SETTLE_HEX
    bt-cli generatetoaddress 1 $btcaddr
}

setup_ln() {
    l2id=$(l2-cli getinfo | jq -r .id)
    l3id=$(l3-cli getinfo | jq -r .id)
    l1addr=$(l1-cli newaddr | jq -r .bech32)
    l2addr=$(l2-cli newaddr | jq -r .bech32)
    bt-cli loadwallet "default"
    btcaddr=$(bt-cli getnewaddress)
    bt-cli sendtoaddress $l1addr 1
    bt-cli sendtoaddress $l2addr 1
    l1-cli connect $l2id@localhost:7272
    l2-cli connect $l3id@localhost:7373
    l1-cli connect $l3id@localhost:7373
    bt-cli generatetoaddress 6 $btcaddr
    sleep 5
    l1-cli fundchannel $l2id 10000 normal false
    l2-cli fundchannel $l3id 10000 normal false
    bt-cli generatetoaddress 6 $btcaddr

    sleep 0.5
    invoice=$(l2-cli invoice 10000 hi "test" | jq -r .bolt11)
    l1-cli pay $invoice
    sleep 0.5
    invoice=$(l2-cli invoice 10000 hi2 "test" | jq -r .bolt11)
    l1-cli pay $invoice
    sleep 0.5
    invoice=$(l2-cli invoice 1000000 hi3 "test" | jq -r .bolt11)
    l1-cli pay $invoice
    sleep 0.5
    invoice=$(l1-cli invoice 500000 hi "test" | jq -r .bolt11)
    l2-cli pay $invoice
    sleep 0.5
    invoice=$(l3-cli invoice 100000 hi "test" | jq -r .bolt11)
    l2-cli pay $invoice

    # We aren't announcing channels, yet, we're considered a "dead
    # end", so shove in routehint
    sleep 0.5
    l3scid=$(l3-cli listchannels | jq -r .channels[0].short_channel_id)
    echo $l3scid
    invoice=$(l3-cli -k invoice msatoshi=10000 label=hi2 description="test" exposeprivatechannels="[${l3scid}]" | jq -r .bolt11)
    l1-cli pay $invoice
}

stop_nodes() {
	if [ -z "$2" ]; then
		network=regtest
	else
		network="$2"
	fi
	if [ -n "$LN_NODES" ]; then
		for i in $(seq $LN_NODES); do
			test ! -f "/tmp/l$i-$network/lightningd-$network.pid" || \
				(kill "$(cat "/tmp/l$i-$network/lightningd-$network.pid")"; \
				rm "/tmp/l$i-$network/lightningd-$network.pid")
			unalias "l$i-cli"
			unalias "l$i-log"
		done
	fi
}

stop_ln() {
	stop_nodes "$1" regtest
	test ! -f "$PATH_TO_BITCOIN/regtest/bitcoind.pid" || \
		(kill "$(cat "$PATH_TO_BITCOIN/regtest/bitcoind.pid")"; \
		rm "$PATH_TO_BITCOIN/regtest/bitcoind.pid")

	unset LN_NODES
	unalias bt-cli
}

start_elem() {
	if [ -z "$PATH_TO_ELEMENTS" ]; then
		if [ -d "$HOME/.elements" ]; then
			PATH_TO_ELEMENTS="$HOME/.elements"
		else
			echo "\$PATH_TO_ELEMENTS not set to a .elements dir" >&2
			return
		fi
	fi

	test -f "$PATH_TO_ELEMENTS/liquid-regtest/bitcoin.pid" || \
		elementsd -chain=liquid-regtest -printtoconsole -logtimestamps -nolisten -validatepegin=0 -con_blocksubsidy=5000000000 -daemon

	# Wait for it to start.
	while ! elements-cli -chain=liquid-regtest ping 2> /tmp/null; do echo "awaiting elementsd..." && sleep 1; done

	# Kick it out of initialblockdownload if necessary
	if elements-cli -chain=liquid-regtest getblockchaininfo | grep -q 'initialblockdownload.*true'; then
		elements-cli -chain=liquid-regtest generatetoaddress 1 "$(elements-cli -chain=liquid-regtest getnewaddress)" > /dev/null
	fi
	alias et-cli='elements-cli -chain=liquid-regtest'

	if [ -z "$1" ]; then
		nodes=2
	else
		nodes="$1"
	fi
	start_nodes "$nodes" liquid-regtest
	echo "	et-cli, stop_elem"
}


stop_elem() {
	stop_nodes "$1" liquid-regtest
	test ! -f "$PATH_TO_ELEMENTS/liquid-regtest/bitcoind.pid" || \
		(kill "$(cat "$PATH_TO_ELEMENTS/liquid-regtest/bitcoind.pid")"; \
		rm "$PATH_TO_ELEMENTS/liquid-regtest/bitcoind.pid")

	unset LN_NODES
	unalias et-cli
}
