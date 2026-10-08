#!/usr/bin/env bash
# Скачивает mz из релиза {{.Tag}}, сверяет его и запускает mz install с аргументами этого скрипта.
# mz сам выпускает якорь и кросс-сертификаты на этом Mac и ставит их в связку ключей login.
#
#   curl -fsSL https://github.com/mikluko/meanziphra/releases/latest/download/install.sh | bash -s -- banks gov
#
# SHA-256 бинарника вписан в этот скрипт; если установлен gh, ещё проверяется аттестация.
set -euo pipefail

repo=mikluko/meanziphra
tag={{sh .Tag}}

die() { echo "install.sh: $*" >&2; exit 1; }

[ "$(uname -s)" = Darwin ] || die "only macOS is supported"
case "$(uname -m)" in
arm64) bin=mz-darwin-arm64 ;;
x86_64) bin=mz-darwin-amd64 ;;
*) die "unsupported architecture $(uname -m)" ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/$bin" "https://github.com/$repo/releases/download/$tag/$bin" || die "cannot download $bin from $tag"

cat >"$tmp/all.sums" <<'SUMS'
{{range .Sums}}{{.}}
{{end -}}
SUMS
grep "  $bin\$" "$tmp/all.sums" >"$tmp/sums"
(cd "$tmp" && shasum -a 256 -c sums >/dev/null) || die "SHA-256 mismatch"

if command -v gh >/dev/null; then
	gh attestation verify "$tmp/$bin" -R "$repo" >/dev/null || die "attestation of $bin does not verify"
	echo "attestation verified"
else
	echo "gh not found: attestation not verified, SHA-256 only" >&2
fi

chmod +x "$tmp/$bin"
"$tmp/$bin" install "$@"
