function fancySats(sats)
{
	if(sats >= 10000000) {
		sats = Math.round(sats / 1000000);
		return sats / 100.0 + "btc"
	}

	if(sats >= 100000) {
		sats = Math.round(sats / 100000);
		return sats / 10.0 + "m sats"
	}

	if(sats >= 1000) {
		sats = Math.round(sats / 10);
		return sats / 100.0 + "k sats"
	}

	if(sats == 1)
		return "1 sat";

	sats = Math.round(sats * 10);
	return sats / 10.0 + " sats"
}

function fancySatDiff(diff)
{
	if(!diff)
		return "";

	if(diff > 0)
		return " + " + fancySats(diff);

	return " - " + fancySats(Math.abs(diff));
}

function status(msg)
{
	console.log(msg);
	// document.getElementById('status').value = msg;
}

function log(msg)
{
	// document.getElementById('log').value = msg;
}

function defaultCallback(obj)
{
	status(JSON.stringify(obj, null, 2));
}

function go(port, onconnect = null)
{
	return;

	go.error = function(msg)
	{
		log("Error: " + msg);
	}

	go.callbacks = [];

	go.hasError = false;
	var buffer = '';
	var timeoutID = null;

	status("Connecting to Core Lightning...");

	/* Command to get nodeid and a rune

	l1-cli getinfo | jq -r ".id" && l1-cli createrune | jq -r ".rune"

	alias lightning-cli=l1-cli

	l1-cli keysend $(l2-cli getinfo | jq -r ".id") 100000sats

	l2-cli keysend $(l1-cli getinfo | jq -r ".id") 100000sats

	*/

	nodeid = "02706faa5bdc4fe13708a3220b512a3346a6a4f04cac2c1d11e4b848bbbc58b7ae";
	rune = "Of2XdLYUb2z1_0FAvakXBAWtbL795SbbvIsD6MC1J3w9NQ==";

	window.gosocket = socket = go.socket = new WebSocket("ws://127.0.0.1:" + port + "/ws?Nodeid=" + nodeid + "&Rune=" + window.encodeURI(rune));

	socket.onopen = function(e)
	{
		status("We are connected to Core Lightning.");
		socket.send("listpeerchannels");
		return;
		if(onconnect)
			onconnect();
	};

	socket.onmessage = function(e)
	{
		status("We got a message! " + e);
		return;
		if(timeoutID)
			clearTimeout(timeoutID);
		timeoutID = null;
		buffer += e.data;
		try {
			obj = JSON.parse(buffer);
			buffer = '';
			if(obj.hasOwnProperty('error'))
				go.error(obj['error']);
			else if(!obj.hasOwnProperty('result'))
				go.error("Malformed response " + buffer);
			else {
				if(go.hasError)
					console.log("JSON chunks consolidated successfully.");
				cb = go.callbacks.pop();
				if(cb)
					cb(obj['result'])
				else
					defaultCallback(obj['result']);
			}
			if(go.hasError) {
				go.hasError = false;
			}
		} catch(err) {
			if(!err.message.startsWith("Unterminated string in JSON")) {
				go.hasError = true;
				console.log(buffer);
				console.log(err.message);
				timeoutID = setTimeout(function()
				{
					console.log("Reseting buffer after delay");
					status("Reseting buffer after delay");
					timeoutID = null;
					buffer = '';
					go.hasError = false;
				}, 3000);
			}
		}
	};

	// socket.onclose = function(e)
	// {
	// 	status("We got a close " + e);
	// 	console.log(e);
	// 	return;
	// 	if(socket.considerFinished)
	// 		return;

	// 	// if (!go.hasError)
	// 	// 	go(port, loop);
	// };

	socket.onerror = function(e)
	{
		status("We got an error " + e);
		return;
		go.hasError = true;
		status("Can't find Core Lightning on port " + document.getElementById('port').value);
		setTimeout(start, 5000);
	};
}

function request(rpcname, result = null)
{
	const port = 3010;
	const url = 'http://127.0.0.1:' + port + '/v1/' + rpcname;
	const data = {};

	const nodeid = document.getElementById("nodeid").value;
	const rune = document.getElementById("rune").value;

	if(!nodeid || !rune)
		return;

	const headers = new Headers();
	headers.append('Nodeid', nodeid);
	headers.append('Rune', rune);

	const requestOptions = {
	  method: 'POST',
	  headers: headers,
	  body: JSON.stringify(data)
	};

	fetch(url, requestOptions)
	  .then(response => response.json())
	  .then(data => {
	    if (result)
	    	result(data)
	  })
	  .catch(error => {
	    console.error('Error:', error);
	  });

	return;


	if(go.hasError)
		return;

	try {
		if(result)
			go.callbacks.push(result);

		go.socket.send(rpcname);
	} catch(e) {

	}
}

loopTimer = null;

function start()
{
	go(document.getElementById('port').value, loop);
}

start();

function restart(portChange)
{
	if(portChange)
		document.getElementById('port').value = document.getElementById('port').value - 0 + portChange;

	go.socket.considerFinished = true;
	go.socket.close();

	start();
}

function getChannelTemplate()
{
	nodes = document.getElementById("channel-list");

	// nodes.replaceChildren(nodes.firstElementChild);

	return nodes.firstElementChild;
}

function clearChannels()
{
	nodes = document.getElementById("channel-list");

	nodes.replaceChildren(nodes.firstElementChild);
}

function clearTransactions()
{
	nodes = document.getElementById("chain_activity");

	nodes.replaceChildren(nodes.firstElementChild);

	return nodes.firstElementChild;
}

function padsats(sats, padleft = true)
{
	sats = "" + sats;
	while(sats.length < 9)
		if(padleft)
			sats = " " + sats;
		else
			sats += " ";
	return sats;
}

function loop()
{
	if(loopTimer)
		clearTimeout(loopTimer);
	loopTimer = setTimeout(loop, 2000);

	function find_or_make_channel(channel_id, template)
	{
		channel_list = document.getElementById("channel-list");

		for(child of channel_list.getElementsByTagName("li"))
			if(child.channel_id == channel_id)
				return child;

		copy = template.cloneNode(true);

		copy.channel_id = channel_id;

		return copy;
	}

	function channels(obj)
	{
		msg = '';

		template = getChannelTemplate();

		for(channel of obj.channels) {
			peer = channel.peer_id.slice(-3);
			scid = channel.short_channel_id;
			channel_id = channel.channel_id;
			txid = channel.funding_txid.slice(0, 3);
			outnum = channel.funding_outnum;
			total = parseInt(channel.total_msat) / 1000;
			mine = parseInt(channel.to_us_msat) / 1000;
			theirs = total - mine;
			state = channel.state;
			mine_change = 0;
			their_change = 0;

			if(channel.hasOwnProperty("inflight") && channel.inflight.length) {
				inflight = channel.inflight.pop();

				total_inf = parseInt(inflight.total_funding_msat) / 1000 + inflight.splice_amount;
				mine_inf = parseInt(inflight.our_funding_msat) / 1000 + inflight.splice_amount;
				// their_inf = total_inf - mine_inf;

				mine_change = mine_inf - mine;
				// their_change = their_inf - theirs;

				total = total_inf;
			}

			is_normal = (state == "CHANNELD_NORMAL");

			if(channel.state_changes.length)
				state += ": " + channel.state_changes.pop()['message'];

			my_percent = (mine + mine_change) / total;

			my_arrow = "-";
			their_arrow = "-";
			my_fr = 1;
			their_fr = 1;

			for(i = 0; i < 10; i++) {
				if(i < my_percent * 10) {
					my_arrow += '-';
					my_fr++;
				}
				else {
					their_arrow += '-';
					their_fr++;
				}
			}

			msg += "[Me] " + padsats(mine) + " " + my_arrow + "><" + their_arrow + " " + padsats(theirs, false) + " [Node " + peer + "] label: '" + txid + "." + outnum + "' " + state;

			if(mine_change)
				msg += ". I adjust by" + fancySatDiff(mine_change);
			if(their_change)
				msg += ". They adjust by" + fancySatDiff(their_change);

			msg += "\n";

			copy = find_or_make_channel(channel_id, template);

			copy.style.display = '';
			copy.style.gridTemplateColumns = "auto " + my_fr + "fr " + their_fr + "fr auto";

			my_bal_str = fancySats(mine) + fancySatDiff(mine_change);
			their_bal_str = fancySats(theirs) + fancySatDiff(their_change);

			if(mine == 0)
				my_bal_str = fancySatDiff(mine_change);;

			if(theirs == 0)
				their_bal_str = fancySatDiff(their_change);

			if(!is_normal) {
				if(mine + mine_change >= theirs + their_change)
					my_bal_str += " ⌛";
				else
					their_bal_str += " ⌛";
			}

			copy.querySelector('.us .text').innerText = my_bal_str;
			copy.querySelector('.them .text').innerText = their_bal_str;

			lbar = copy.querySelector('.bar.us');
			rbar = copy.querySelector('.bar.them');

			rname = copy.getElementsByTagName("abbr")[1];

			rname.innerText = peer;
			rname.title = channel.peer_id;

			if(mine + mine_change == 0) {
				lbar.style.display = 'none';
				copy.style.gridTemplateColumns = "auto 1fr auto";
			}
			else
				lbar.style.display = '';

			if(theirs + their_change == 0) {
				rbar.style.display = 'none';
				copy.style.gridTemplateColumns = "auto 1fr auto";
			}
			else
				rbar.style.display = '';

			if(!is_normal) {
				copy.classList.add('pending');
			}

			if(!copy.parentNode)
				template.parentNode.appendChild(copy);
		}

		h2 = document.getElementById("NoChannels");

		if(!h2) {
			h2 = template.parentNode.appendChild(document.createElement('h2'));
			h2.id = "NoChannels";
			h2.innerText = "No channels";
		}

		if(msg.length)
			h2.style.display = 'none';
		else
			h2.style.display = '';

		// document.getElementById('channels').value = msg;
	}

	function scriptPubKeyMatch(outputs, utxo)
	{
		for(output of tx.outputs) {
			if(output.scriptPubKey == utxo.scriptPubKey) {
				return true;
			}
		}
		return false;
	}

	function transaction(tx, template)
	{
		copy = template.cloneNode(true);
		copy.style.display = '';
		h3 = copy.getElementsByTagName("h3")[0];
		ul = copy.getElementsByTagName("ul")[0];

		msg = '';
		if(!tx.blockheight)
			msg += h3.innerText = "Pending onchain movement"
		else
			msg += h3.innerText = "Block Height " + tx.blockheight;
		msg += ":\n";
		txid = tx.hash.slice(0, 3);
		spent_labels = "Spent label" + (tx.inputs.length == 1 ? ": " : "s: ");
		i = 0;
		preserved_splices = {};
		withdrawls = 0;
		splice_outs = 0;
		for(input of tx.inputs) {
			if(i++)
				spent_labels += ", ";
			spent_labels += "'";
			spent_labels += input.txid.slice(0, 3) + '.' + input.index + "'";

			if((input.txid + input.index) in txtrack) {
				utxo = txtrack[input.txid + input.index];

				if(utxo.hasOwnProperty('type')) {

					if(utxo.type == "deposit")
						withdrawls += parseInt(utxo.amount_msat) / 1000;

					if(utxo.type == "channel_funding") {

						amount = parseInt(utxo.amount_msat) / 1000;

						input.amount = amount

						preserved_splices[utxo.scriptPubKey] = input;

						str = "Channel out " + fancySats(amount) + " ➡️";

						if(!scriptPubKeyMatch(tx.outputs, utxo)) {
							splice_outs += amount;
							ul.appendChild(document.createElement("li")).innerText = str;
						}
					}
				}
			}
		}
		msg += spent_labels + "\n";
		deposits = 0;
		channel_funding = 0;
		for(output of tx.outputs) {

			htmlstr = fancySats(parseInt(output.amount_msat) / 1000);
			msg += "\t+" + parseInt(output.amount_msat) / 1000 + "sat to label ";
			label = "'" + txid + '.' + output.index + "'";
			msg += label + ";";
			if(output.hasOwnProperty('type')) {
				msg += " type " + output.type;
				htmlstr += " to " + output.type;

				if(output.type == "deposit") {
					deposits += parseInt(output.amount_msat) / 1000;
					htmlstr = null;
				}

				if(output.type == "channel_funding") {
					amount = parseInt(output.amount_msat) / 1000;

					input = preserved_splices[output.scriptPubKey];

					old_chan_id = null;
					new_chan_id = "\"" + txid + '.' + output.index + "\"";

					if(input) {
						amount -= input.amount;
						old_chan_id = "\"" + input.txid.slice(0, 3) + '.' + input.index + "\"";
					}

					channel_funding += amount;

					if(output.scriptPubKey in txtrack) {

						if(amount > 0)
							htmlstr = "Splice " + fancySats(amount) + " into channel " + old_chan_id + "; relabeled " + new_chan_id;
						else
							htmlstr = "Splice " + fancySats(-amount) + " out of channel " + old_chan_id + "; relabeled " + new_chan_id;
					}
					else
						htmlstr = "New " + fancySats(amount) + " channel \"" + txid + '.' + output.index + "\"";
				}
			}
			else {
				msg += " type not_mine"
				htmlstr = null;
			}
			// htmlstr += " label " + label;
			msg += "\n";
			if(htmlstr)
				ul.appendChild(document.createElement("li")).innerText = htmlstr;

			txtrack[tx.hash + output.index] = output;
			txtrack[output.scriptPubKey] = output;
		}
		deposits += channel_funding;
		withdrawls += splice_outs;
		if(deposits < withdrawls) {
			htmlstr = "Spend " + fancySats(withdrawls - deposits);
			ul.appendChild(document.createElement("li")).innerText = htmlstr;
		}
		if(deposits > withdrawls) {
			htmlstr = "Deposit " + fancySats(deposits - withdrawls);
			ul.appendChild(document.createElement("li")).innerText = htmlstr;
		}
		template.parentNode.insertBefore(copy, template.nextSibling);
		msg += "\n";
		return msg;
	}

	function transactions(obj)
	{
		msg = '';

		template = clearTransactions();
		txtrack = {};

		for(tx of obj.transactions)
			if(tx.blockheight)
				msg += transaction(tx, template, txtrack);

		for(tx of obj.transactions)
			if(!tx.blockheight)
				msg += transaction(tx, template, txtrack);

		if(!msg.length)
			msg = "Nothing found onchain.";

		//document.getElementById('onchain').value = msg;
	}

	function gotinfo(obj)
	{
		me = obj.id.slice(-3);

		if(me)
			document.getElementById("title").innerText = "Core Lightning " + me;
	}

	function cb(obj)
	{
		if(obj.hasOwnProperty("transactions"))
			transactions(obj);

		if(obj.hasOwnProperty("channels"))
			channels(obj);

		if(obj.hasOwnProperty("our_features"))
			gotinfo(obj);
	}

	setTimeout(function() {
		request("listpeerchannels", cb);
	}, Math.floor(Math.random() * 200) + 1);
	setTimeout(function() {
		request("listtransactions", cb);
	}, Math.floor(Math.random() * 200) + 1);
	setTimeout(function() {
		request("getinfo", cb);
	}, Math.floor(Math.random() * 200) + 1);
}

request("listpeerchannels");
loop();

document.onkeydown = function(e)
{
	e ||= window.event;
	if(e.keyCode == 37) // left
		restart(-1);
	if(e.keyCode == 39) // right
		restart(1);
}
