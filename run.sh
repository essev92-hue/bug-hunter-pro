1#!/data/data/com.termux.nix/files/usr/bin/bash

echo "Loading Bug Hunter Pro with nix-shell..."
echo "This may take a moment..."

nix-shell -p \
  bash \
  coreutils \
  findutils \
  gnugrep \
  gawk \
  gnused \
  curl \
  git \
  ncurses \
  python3 \
  sqlite \
  nodejs \
  nmap \
  jq \
  --run "
    echo '✓ All tools loaded successfully!'
    echo '✓ Starting Bug Hunter Pro...'
    echo ''
    ./bug-hunter-pro.sh
"
