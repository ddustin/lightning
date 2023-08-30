






l1-cli getinfo | jq -r ".id"; l1-cli createrune | jq -r ".rune" | pbcopy; pbpaste






alias lightning-cli=l1-cli








l1-cli keysend $(l2-cli getinfo | jq -r ".id") 100000sats



l2-cli keysend $(l1-cli getinfo | jq -r ".id") 100000sats




bt-cli generatetoaddress 6 $ADDRESS

