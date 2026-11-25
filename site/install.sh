#!/bin/sh
# Install ssheep.
#
# Very early software. Not audited. Read https://ssheep.xyz before you run this.
#
#   curl -fsSL https://ssheep.xyz/install.sh | sh
#   curl -fsSL https://ssheep.xyz/install.sh | sh -s -- /usr/local/bin/ssheep
#
set -eu

repo=bash3r777/ssheep
dest=${1:-/usr/local/bin/ssheep}

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

echo "ssheep: fetching $url"
if ! curl -fsSL "$url" -o "$dest.tmp" 2>/dev/null; then
  echo "ssheep: download failed." >&2
  echo "ssheep: no release yet? build it instead:" >&2
  echo "  git clone https://github.com/$repo && cd ssheep && make build" >&2
  exit 1
fi
chmod 755 "$dest.tmp"
mv "$dest.tmp" "$dest"
echo "ssheep: installed $dest"
"$dest" version
