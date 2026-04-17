#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Bootstrap host dependencies for SyzDirect on Ubuntu/WSL.

Usage:
  bash scripts/bootstrap_host.sh [--yes] [--skip-kvm-group]

Options:
  --yes             Pass -y to apt-get install.
  --skip-kvm-group  Do not add the current user to the kvm group.
  -h, --help        Show this help.
EOF
}

APT_YES=()
SKIP_KVM_GROUP=0

while [ $# -gt 0 ]; do
    case "$1" in
        --yes)
            APT_YES=(-y)
            ;;
        --skip-kvm-group)
            SKIP_KVM_GROUP=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown option: %s\n\n' "$1" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

SUDO=()
if [ "$(id -u)" -ne 0 ]; then
    if ! command -v sudo >/dev/null 2>&1; then
        printf '[ERROR] sudo is required to install host packages.\n' >&2
        exit 1
    fi
    SUDO=(sudo)
fi

PACKAGES=(
    bc
    bison
    build-essential
    ca-certificates
    curl
    debootstrap
    dwarves
    flex
    gcc
    git
    golang-go
    libelf-dev
    libncurses-dev
    libssl-dev
    make
    openssh-client
    python3
    python3-pip
    qemu-system-x86
    qemu-utils
    zstd
)

printf '[INFO] Updating apt metadata...\n'
"${SUDO[@]}" apt-get update

printf '[INFO] Installing host packages...\n'
"${SUDO[@]}" apt-get install "${APT_YES[@]}" "${PACKAGES[@]}"

if [ "$SKIP_KVM_GROUP" -eq 0 ] && getent group kvm >/dev/null 2>&1; then
    TARGET_USER="${SUDO_USER:-${USER:-}}"
    if [ -n "$TARGET_USER" ] && id "$TARGET_USER" >/dev/null 2>&1; then
        if id -nG "$TARGET_USER" | tr ' ' '\n' | grep -qx kvm; then
            printf '[INFO] %s is already in the kvm group.\n' "$TARGET_USER"
        else
            printf '[INFO] Adding %s to the kvm group...\n' "$TARGET_USER"
            "${SUDO[@]}" usermod -aG kvm "$TARGET_USER"
            printf '[WARN] Re-login or restart the shell to pick up kvm group membership.\n'
        fi
    fi
fi

printf '[INFO] Host bootstrap complete.\n'
