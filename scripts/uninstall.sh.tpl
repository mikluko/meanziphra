#!/usr/bin/env bash
# Удаляет из связки ключей login якорь meanziphra и все выпущенные им кросс-сертификаты.
#
#   curl -fsSL https://github.com/mikluko/meanziphra/releases/latest/download/uninstall.sh | bash
set -euo pipefail

anchor_name={{sh .AnchorName}}
keychain=${MEANZIPHRA_KEYCHAIN:-$HOME/Library/Keychains/login.keychain-db}

[ "$(uname -s)" = Darwin ] || { echo "uninstall.sh: only macOS is supported" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

security find-certificate -a -p "$keychain" 2>/dev/null |
	awk -v d="$tmp" '/BEGIN CERT/{n++; f=d "/kc-" n ".pem"} n{print > f}'
removed=0
for p in "$tmp"/kc-*.pem; do
	[ -e "$p" ] || continue
	issuer=$(openssl x509 -in "$p" -noout -issuer -nameopt utf8,sep_comma_plus 2>/dev/null) || continue
	issuer=${issuer#issuer=}
	issuer=${issuer# }
	[ "$issuer" = "CN=$anchor_name" ] || continue
	sha=$(openssl x509 -in "$p" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d :)
	security delete-certificate -t -Z "$sha" "$keychain" >/dev/null
	echo "removed $sha"
	removed=$((removed + 1))
done
echo "done: removed $removed certificates of $anchor_name"
