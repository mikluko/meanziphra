#!/usr/bin/env bash
# Ставит якорь «{{.AnchorName}}» и кросс-сертификаты из каталога этого скрипта в системное хранилище корневых
# сертификатов Linux (curl, wget, Python и всё на OpenSSL или GnuTLS), а если есть certutil и база NSS
# пользователя ~/.pki/nssdb — ещё и туда (Chrome). Firefox держит свою базу в профиле: туда скрипт не пишет.
#
#   bash install.sh
#
# Системному хранилищу нужен root: без него скрипт перезапускает себя через sudo. Прежние сертификаты
# этого бандла удаляются. SHA-256 файлов вписаны в этот скрипт при сборке бандла.
set -euo pipefail

anchor_name={{sh .AnchorName}}
crosses=({{range .Crosses}}{{sh .}} {{end}})
dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

die() { echo "install.sh: $*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || die "this bundle is for Linux; build one with mz bundle -target macos for a Mac"
if [ "$(id -u)" -ne 0 ]; then
	exec sudo bash "$dir/install.sh" "$@"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cat >"$tmp/sums" <<'SUMS'
{{range .Sums}}{{.}}
{{end -}}
SUMS
(cd "$dir" && sha256sum -c --quiet "$tmp/sums") || die "SHA-256 mismatch"

if [ -d /usr/local/share/ca-certificates ] && command -v update-ca-certificates >/dev/null; then
	store=/usr/local/share/ca-certificates
	update=(update-ca-certificates)
elif [ -d /etc/pki/ca-trust/source/anchors ] && command -v update-ca-trust >/dev/null; then
	store=/etc/pki/ca-trust/source/anchors
	update=(update-ca-trust extract)
else
	die "no supported system trust store: need update-ca-certificates or update-ca-trust"
fi

rm -f "$store"/meanziphra-*.crt
install -m 0644 "$dir/anchor.crt" "$store/meanziphra-anchor.crt"
for f in "${crosses[@]}"; do install -m 0644 "$dir/$f" "$store/meanziphra-$f"; done
"${update[@]}" >/dev/null
echo "system trust store: $store"

user=${SUDO_USER:-root}
home=$(getent passwd "$user" | cut -d: -f6)
db="$home/.pki/nssdb"
if command -v certutil >/dev/null && [ -d "$db" ]; then
	as_user() { if [ "$user" = root ]; then "$@"; else sudo -u "$user" "$@"; fi; }
	for n in $(as_user certutil -L -d "sql:$db" | awk '$1 ~ /^meanziphra-/ {print $1}'); do
		as_user certutil -D -d "sql:$db" -n "$n"
	done
	as_user certutil -A -d "sql:$db" -n meanziphra-anchor -t C,, -a -i "$dir/anchor.crt"
	for f in "${crosses[@]}"; do as_user certutil -A -d "sql:$db" -n "meanziphra-${f%.crt}" -t ,, -a -i "$dir/$f"; done
	echo "NSS database: $db"
fi
echo "done: $anchor_name"
