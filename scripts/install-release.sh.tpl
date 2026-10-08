#!/usr/bin/env bash
# Скачивает mz из релиза {{.Tag}}, сверяет его и запускает mz install с аргументами этого скрипта.
# mz сам выпускает якорь и кросс-сертификаты на этом компьютере и ставит их: в macOS — в связку ключей login,
# в Linux — в системное хранилище и в базу NSS пользователя.
#
#   curl -fsSL https://github.com/mikluko/meanziphra/releases/latest/download/install.sh | bash -s -- banks gov
#
# SHA-256 бинарника вписан в этот скрипт; если установлен gh, ещё проверяется аттестация.
set -euo pipefail

repo=mikluko/meanziphra
tag={{sh .Tag}}

die() { echo "install.sh: $*" >&2; exit 1; }

case "$(uname -s)" in
Darwin) os=darwin ;;
Linux) os=linux ;;
*) die "unsupported system $(uname -s)" ;;
esac
case "$(uname -m)" in
arm64 | aarch64) bin=mz-$os-arm64 ;;
x86_64) bin=mz-$os-amd64 ;;
*) die "unsupported architecture $(uname -m)" ;;
esac
if command -v sha256sum >/dev/null; then sha=(sha256sum); else sha=(shasum -a 256); fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/$bin" "https://github.com/$repo/releases/download/$tag/$bin" || die "cannot download $bin from $tag"

cat >"$tmp/all.sums" <<'SUMS'
{{range .Sums}}{{.}}
{{end -}}
SUMS
grep "  $bin\$" "$tmp/all.sums" >"$tmp/sums"
(cd "$tmp" && "${sha[@]}" -c sums >/dev/null) || die "SHA-256 mismatch"

if command -v gh >/dev/null; then
	gh attestation verify "$tmp/$bin" -R "$repo" >/dev/null || die "attestation of $bin does not verify"
	echo "attestation verified"
else
	echo "gh not found: attestation not verified, SHA-256 only" >&2
fi

chmod +x "$tmp/$bin"
"$tmp/$bin" install "$@"
