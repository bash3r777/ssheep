#!/bin/sh
# Install ssheep.
#
# Very early software. Not audited. Read https://ssheep.xyz before you run this.
#
#   curl -fsSL https://ssheep.xyz/install.sh | sh
#   curl -fsSL https://ssheep.xyz/install.sh | sh -s -- /usr/local/bin/ssheep
#   curl -fsSL https://ssheep.xyz/install.sh | sh -s -- --ticket "<ticket>"
#
# With --ticket it joins the flock the ticket is for, by the full path it just
# installed to — so it works whether or not that directory happens to be on PATH,
# and the role comes from the ticket rather than from what you typed.
set -eu

repo=bash3r777/ssheep

dest=""
ticket=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ticket)
      if [ $# -lt 2 ]; then echo "ssheep: --ticket needs a value" >&2; exit 2; fi
      ticket=$2
      shift 2
      ;;
    --ticket=*)
      ticket=${1#--ticket=}
      shift
      ;;
    -h|--help)
      echo "usage: install.sh [install-path] [--ticket TICKET]" >&2
      exit 0
      ;;
    -*)
      echo "ssheep: unknown option: $1" >&2
      exit 2
      ;;
    *)
      dest=$1
      shift
      ;;
  esac
done

# Where to put it. /usr/local/bin when we can, otherwise the user's own bin, so
# the one-liner works without sudo on a machine that has never seen this before.
if [ -z "$dest" ]; then
  if [ -w /usr/local/bin ] 2>/dev/null; then
    dest=/usr/local/bin/ssheep
  else
    dest=${HOME:-/tmp}/.local/bin/ssheep
  fi
fi

os=$(uname -s | tr 'A-Z' 'a-z')
case "$os" in
  linux|darwin) ;;
  *) echo "ssheep: unsupported operating system: $os" >&2; exit 1 ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64|amd64)  arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "ssheep: unsupported architecture: $arch" >&2; exit 1 ;;
esac

url="https://github.com/$repo/releases/latest/download/ssheep-$os-$arch"

echo "installing... 10%"
mkdir -p "$(dirname "$dest")"
if ! curl -fsSL "$url" -o "$dest.tmp" 2>/dev/null; then
  echo "ssheep: download failed." >&2
  echo "ssheep: no release yet? build it instead:" >&2
  echo "  git clone https://github.com/$repo && cd ssheep && make build" >&2
  exit 1
fi
echo "installing... 50%"
chmod 755 "$dest.tmp"
mv "$dest.tmp" "$dest"
echo "installing... 90%"
"$dest" version >/dev/null 2>&1 || true
echo "Installation complete!"

# Joining is the installer's job when a ticket was handed to it, so the whole of
# onboarding is one command instead of two.
if [ -n "$ticket" ]; then
  echo
  exec "$dest" join "$ticket"
fi

case ":$PATH:" in
  *":$(dirname "$dest"):"*) ;;
  *) echo "ssheep: note: $(dirname "$dest") is not in your PATH" ;;
esac
echo "ssheep: next: ssheep master flock \"myflock\"   (or hand a ticket to this script)"
