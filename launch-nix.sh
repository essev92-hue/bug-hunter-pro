#!/usr/bin/env bash

# Load Nix fixes
source ~/bug-hunter-pro/nix-fixes.sh

# Fix beberapa variabel environment
export TERMUX="/data/data/com.termux/files/home"
export PREFIX="/nix/var/nix/profiles/per-user/$(whoami)/profile"

# Check jika di Nix on Droid
if [ -d "/nix" ] && [ -d "/data/data/com.termux" ]; then
    echo "Running on Nix on Droid..."
    
    # Setup pseudo-termux environment
    mkdir -p /data/data/com.termux/files/usr/bin 2>/dev/null || true
    mkdir -p /data/data/com.termux/files/home 2>/dev/null || true
    
    # Run main script dengan environment khusus
    env -i \
        HOME="$HOME" \
        USER="$(whoami)" \
        PATH="/nix/var/nix/profiles/per-user/$(whoami)/profile/bin:/usr/bin:/bin" \
        SHELL="/nix/var/nix/profiles/per-user/$(whoami)/profile/bin/bash" \
        PREFIX="/nix/var/nix/profiles/per-user/$(whoami)/profile" \
        TERMUX="/data/data/com.termux/files/home" \
        bash ~/bug-hunter-pro/bug-hunter-pro.sh "$@"
else
    echo "Not running on Nix on Droid. Running normally..."
    bash ~/bug-hunter-pro/bug-hunter-pro.sh "$@"
fi
