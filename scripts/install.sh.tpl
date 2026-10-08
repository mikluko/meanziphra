#!/usr/bin/env bash
# Ставит якорь meanziphra и кросс-сертификаты выбранных категорий из релиза {{.Tag}} в связку ключей login.
#
#   curl -fsSL https://github.com/mikluko/meanziphra/releases/latest/download/install.sh | bash -s -- banks gov
#
# Прежние сертификаты этого якоря удаляются. Если установлен gh, аттестация каждого файла проверяется
# через gh attestation verify; без gh проверяются только SHA-256, вписанные в этот скрипт.
set -euo pipefail

repo=mikluko/meanziphra
tag={{sh .Tag}}
anchor_name={{sh .AnchorName}}
categories=({{range .Categories}}{{sh .}} {{end}})
keychain=${MEANZIPHRA_KEYCHAIN:-$HOME/Library/Keychains/login.keychain-db}

die() { echo "install.sh: $*" >&2; exit 1; }

if [ $# -eq 0 ]; then
	echo "usage: install.sh <category>... | all" >&2
	echo "categories: ${categories[*]}" >&2
	exit 2
fi
[ "$(uname -s)" = Darwin ] || die "only macOS is supported"

selected=()
for arg in "$@"; do
	if [ "$arg" = all ]; then
		selected=("${categories[@]}")
		break
	fi
	found=
	for c in "${categories[@]}"; do [ "$c" = "$arg" ] && found=1; done
	[ -n "$found" ] || die "unknown category $arg; categories: ${categories[*]}"
	selected+=("$arg")
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

files=(anchor.crt)
for c in "${selected[@]}"; do files+=("cat-$c.crt"); done

base="https://github.com/$repo/releases/download/${tag//+/%2B}"
for f in "${files[@]}"; do
	curl -fsSL -o "$tmp/$f" "$base/$f" || die "cannot download $f from $tag"
done

cat >"$tmp/all.sums" <<'SUMS'
{{range .Sums}}{{.}}
{{end -}}
SUMS
for f in "${files[@]}"; do grep "  $f\$" "$tmp/all.sums"; done >"$tmp/sums"
(cd "$tmp" && shasum -a 256 -c sums >/dev/null) || die "SHA-256 mismatch"

if command -v gh >/dev/null; then
	for f in "${files[@]}"; do
		gh attestation verify "$tmp/$f" -R "$repo" >/dev/null || die "attestation of $f does not verify"
	done
	echo "attestations verified"
else
	echo "gh not found: attestations not verified, SHA-256 only" >&2
fi

# ours перечисляет SHA-1 сертификатов связки, выпущенных якорем с CN anchor_name, включая сам якорь.
ours() {
	security find-certificate -a -p "$keychain" 2>/dev/null |
		awk -v d="$tmp" '/BEGIN CERT/{n++; f=d "/kc-" n ".pem"} n{print > f}'
	for p in "$tmp"/kc-*.pem; do
		[ -e "$p" ] || continue
		issuer=$(openssl x509 -in "$p" -noout -issuer -nameopt utf8,sep_comma_plus 2>/dev/null) || continue
		issuer=${issuer#issuer=}
		issuer=${issuer# }
		if [ "$issuer" = "CN=$anchor_name" ]; then
			openssl x509 -in "$p" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d :
		fi
		rm -f "$p"
	done
}

for sha in $(ours); do
	security delete-certificate -t -Z "$sha" "$keychain" >/dev/null
	echo "removed $sha"
done

echo "trusting $anchor_name; macOS asks for your password"
security add-trusted-cert -r trustRoot -k "$keychain" "$tmp/anchor.crt"
for c in "${selected[@]}"; do
	awk -v d="$tmp" -v c="$c" '/BEGIN CERT/{n++; f=d "/" c "-" n ".pem"} n{print > f}' "$tmp/cat-$c.crt"
	for p in "$tmp/$c"-*.pem; do security add-certificates -k "$keychain" "$p"; done
	echo "installed $c"
done
echo "done: $anchor_name ($tag), categories: ${selected[*]}"
