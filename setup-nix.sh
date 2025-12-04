#!/data/data/com.termux.nix/files/usr/bin/bash

echo "Setting up Nix environment for Bug Hunter Pro..."

# Add Nix to PATH if not already
if [ -f ~/.nix-profile/etc/profile.d/nix.sh ]; then
    source ~/.nix-profile/etc/profile.d/nix.sh
fi

# Install minimal tools via nix-shell (should always work)
nix-shell -p bash coreutils findutils grep gawk gnused curl git ncurses python3 sqlite --run "
    echo 'Tools installed successfully!'
    echo 'Now you can run: ./bug-hunter-pro.sh'
"

echo "Setup complete!"
