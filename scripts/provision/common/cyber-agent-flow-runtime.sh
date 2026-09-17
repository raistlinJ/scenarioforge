#!/bin/bash
# Run as root during provisioning, while the temporary Internet NIC is attached.
set -euo pipefail

apt-get install -y docker.io docker-compose curl ca-certificates
systemctl enable --now docker.service
usermod -aG docker participant

# Use a fresh participant session so Docker's supplementary group is effective.
sudo -H -u participant docker info >/dev/null
sudo -H -u participant docker compose version
sudo -H -u participant docker-compose version

# The native CLI belongs to the desktop user, including its update directory.
sudo -H -u participant bash -s <<'CAF_CLAUDE'
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
if [[ ! -x "$HOME/.local/bin/claude" ]]; then
    installer="$(mktemp)"
    trap 'rm -f "$installer"' EXIT
    curl --fail --silent --show-error --location https://claude.ai/install.sh --output "$installer"
    bash "$installer" stable
fi
"$HOME/.local/bin/claude" --version
CAF_CLAUDE
