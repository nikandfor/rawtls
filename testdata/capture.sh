#!/usr/bin/env bash
# capture.sh records the first TLS connection of a client through cmd/rawtls relay:
# NAME_client.bin and NAME_server.bin are the streams up to the client's first application record,
# NAME_client.keylog is the client's key log for that connection.
#
#	capture.sh chrome gg www.google.com    headless Chrome to the host
#	capture.sh reality re_gg               xray REALITY client to xray REALITY server with www.google.com target
#
# Binaries are taken from PATH, or set rawtls=... xray=... chrome=...
# keep=1 keeps the temporary directory with the logs.
# rawtls is go build ./cmd/rawtls, xray is go build ./main in xray-core.

out="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"

rawtls="${rawtls:-rawtls}"
xray="${xray:-xray}"
chrome="${chrome:-google-chrome}"

# REALITY parameters, the key pair is made by xray x25519.
reality_private=MCxwd4H7MPWzM2v_3TSvn-B17wPhIUQ0lMV591pcHWU
reality_public=W42f3I6s9osnFDuBTa4pi0duXnG6MCglihaJ3IVP3Bw
reality_shortid=0123456789abcdef
reality_uuid=b77f285a-f92c-44f6-9151-40a395904c4e

traps=()

if [ -z "$keep" ]; then
	traps+=("rm -rf '$tmp'")
fi

function defer {
	traps+=("$*")
}

function exit_code {
	local i

	for ((i = ${#traps[@]} - 1; i >= 0; i--)); do
		eval "${traps[i]}"
	done
}

trap exit_code EXIT

function run {
	printf '%q ' "$@" >&2
	echo >&2

	"$@"
}

function relay { # name target
	run "$rawtls" -listen 127.0.0.1:6443 -target "$2" -save "$tmp/$1_XXX.bin" 2>"$tmp/relay.log" &
	relaypid=$!

	sleep 0.5
}

function stop_relay {
	kill -INT "$relaypid"
	wait "$relaypid"

	grep -E 'saved|error' "$tmp/relay.log" >&2
}

function save { # name
	local random

	random="$(od -An -tx1 -j11 -N32 "$tmp/$1_client.bin" | tr -d ' \n')" &&
	grep " $random " "$tmp/keylog.txt" >"$tmp/$1_client.keylog" &&
	cp "$tmp/$1_client.bin" "$tmp/$1_server.bin" "$tmp/$1_client.keylog" "$out/" &&
	echo "saved $1: client random $random" >&2
}

function chrome { # name host
	relay "$1" "$2:443"

	SSLKEYLOGFILE="$tmp/keylog.txt" run timeout 30 "$chrome" --headless=new --no-sandbox --disable-quic \
		--user-data-dir="$tmp/profile" --no-first-run --disable-background-networking \
		--host-resolver-rules="MAP $2:443 127.0.0.1:6443" --dump-dom "https://$2/" >/dev/null 2>"$tmp/chrome.log"

	stop_relay
	save "$1"
}

function reality { # name
	cat >"$tmp/server.json" <<-EOF
	{
	  "inbounds": [{
	    "listen": "127.0.0.1", "port": 7443, "protocol": "vless",
	    "settings": {"clients": [{"id": "$reality_uuid"}], "decryption": "none"},
	    "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
	      "target": "www.google.com:443",
	      "serverNames": ["www.google.com"],
	      "privateKey": "$reality_private",
	      "shortIds": ["$reality_shortid"]
	    }}
	  }],
	  "outbounds": [{"protocol": "freedom"}]
	}
	EOF

	cat >"$tmp/client.json" <<-EOF
	{
	  "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks"}],
	  "outbounds": [{
	    "protocol": "vless",
	    "settings": {"vnext": [{"address": "127.0.0.1", "port": 6443, "users": [{"id": "$reality_uuid", "encryption": "none"}]}]},
	    "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
	      "fingerprint": "chrome",
	      "serverName": "www.google.com",
	      "password": "$reality_public",
	      "shortId": "$reality_shortid",
	      "masterKeyLog": "$tmp/keylog.txt"
	    }}
	  }]
	}
	EOF

	run "$xray" run -c "$tmp/server.json" >"$tmp/xray_server.log" 2>&1 &
	defer kill $!

	run "$xray" run -c "$tmp/client.json" >"$tmp/xray_client.log" 2>&1 &
	local client=$!
	defer kill "$client" 2>/dev/null

	relay "$1" 127.0.0.1:7443

	run curl -sS -o /dev/null --max-time 20 --socks5-hostname 127.0.0.1:1080 https://example.com/

	kill "$client" # closes the relayed connection
	stop_relay
	save "$1"
}

"$@"
