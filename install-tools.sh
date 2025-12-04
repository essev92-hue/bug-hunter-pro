#!/bin/bash
echo "Installing required tools..."
nix-env -i sqlite 2>/dev/null
nix-env -i curl 2>/dev/null
nix-env -i git 2>/dev/null
nix-env -i python3 2>/dev/null
echo "Installation complete!"
echo "Now running bug-hunter-pro..."
./bug-hunter-pro.sh
