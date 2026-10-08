#!/usr/bin/env bash
# Удаляет якорь «{{.AnchorName}}» и кросс-сертификаты meanziphra из системного хранилища Linux и из базы NSS
# пользователя ~/.pki/nssdb. Системному хранилищу нужен root: без него скрипт перезапускает себя через sudo.
set -euo pipefail

die() { echo "uninstall.sh: $*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || die "this script is for Linux"
if [ "$(id -u)" -ne 0 ]; then
	self=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")
	exec sudo bash "$self" "$@"
fi

# remove_from удаляет файлы meanziphra из хранилища store и перестраивает его командой update.
remove_from() {
	local store=$1
	shift
	if [ -d "$store" ] && ls "$store"/meanziphra-*.crt >/dev/null 2>&1; then
		rm -f "$store"/meanziphra-*.crt
		"$@" >/dev/null
		echo "removed from $store"
	fi
}
remove_from /usr/local/share/ca-certificates update-ca-certificates
remove_from /etc/pki/ca-trust/source/anchors update-ca-trust extract

user=${SUDO_USER:-root}
home=$(getent passwd "$user" | cut -d: -f6)
db="$home/.pki/nssdb"
if command -v certutil >/dev/null && [ -d "$db" ]; then
	as_user() { if [ "$user" = root ]; then "$@"; else sudo -u "$user" "$@"; fi; }
	for n in $(as_user certutil -L -d "sql:$db" | awk '$1 ~ /^meanziphra-/ {print $1}'); do
		as_user certutil -D -d "sql:$db" -n "$n"
		echo "removed $n from $db"
	done
fi
echo "done"
