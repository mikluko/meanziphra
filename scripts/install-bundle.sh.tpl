#!/usr/bin/env bash
# Ставит якорь «{{.AnchorName}}» и кросс-сертификаты категорий из каталога этого скрипта в связку ключей login.
# Сеть не нужна: бандл собран командой mz bundle и переносится на другой Mac как есть.
#
#   bash install.sh            все категории бандла
#   bash install.sh banks gov  только перечисленные
#
# Прежние сертификаты этого якоря удаляются. SHA-256 файлов вписаны в этот скрипт при сборке бандла.
set -euo pipefail

anchor_name={{sh .AnchorName}}
categories=({{range .Categories}}{{sh .}} {{end}})
keychain=${MEANZIPHRA_KEYCHAIN:-$HOME/Library/Keychains/login.keychain-db}
dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

die() { echo "install.sh: $*" >&2; exit 1; }

[ "$(uname -s)" = Darwin ] || die "only macOS is supported"

selected=()
if [ $# -eq 0 ]; then
	selected=("${categories[@]}")
fi
for arg in "$@"; do
	found=
	for c in "${categories[@]}"; do [ "$c" = "$arg" ] && found=1; done
	[ -n "$found" ] || die "unknown category $arg; categories: ${categories[*]}"
	selected+=("$arg")
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

files=(anchor.crt)
for c in "${selected[@]}"; do files+=("cat-$c.crt"); done

cat >"$tmp/all.sums" <<'SUMS'
{{range .Sums}}{{.}}
{{end -}}
SUMS
for f in "${files[@]}"; do grep "  $f\$" "$tmp/all.sums"; done >"$tmp/sums"
(cd "$dir" && shasum -a 256 -c "$tmp/sums" >/dev/null) || die "SHA-256 mismatch"

security find-certificate -a -p "$keychain" 2>/dev/null |
	awk -v d="$tmp" '/BEGIN CERT/{n++; f=d "/kc-" n ".pem"} n{print > f}'
for p in "$tmp"/kc-*.pem; do
	[ -e "$p" ] || continue
	issuer=$(openssl x509 -in "$p" -noout -issuer -nameopt utf8,sep_comma_plus 2>/dev/null) || continue
	issuer=${issuer#issuer=}
	issuer=${issuer# }
	[ "$issuer" = "CN=$anchor_name" ] || continue
	sha=$(openssl x509 -in "$p" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d :)
	security delete-certificate -t -Z "$sha" "$keychain" >/dev/null
	echo "removed $sha"
done

echo "trusting $anchor_name; macOS asks for your password"
security add-trusted-cert -r trustRoot -k "$keychain" "$dir/anchor.crt"
for c in "${selected[@]}"; do
	awk -v d="$tmp" -v c="$c" '/BEGIN CERT/{n++; f=d "/" c "-" n ".pem"} n{print > f}' "$dir/cat-$c.crt"
	for p in "$tmp/$c"-*.pem; do security add-certificates -k "$keychain" "$p"; done
	echo "installed $c"
done
echo "done: $anchor_name, categories: ${selected[*]}"
