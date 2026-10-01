#!/bin/sh
# wooma installer: builds from source with cargo, then sets up ICMP permissions.
#
#   curl -fsSL https://raw.githubusercontent.com/B33BMO/wooma/main/install.sh | sh
#
# Non-interactive use: WOOMA_ICMP=sysctl|setcap|skip picks the permission fix
# without asking.
set -eu

REPO="https://github.com/B33BMO/wooma"
USER_PATH=$PATH

info() { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# stdin is the script itself when piped from curl, so questions go to the terminal.
has_tty() { [ -r /dev/tty ] && [ -w /dev/tty ]; }

ask() {
    # ask "question" default -> echoes the answer
    if has_tty; then
        printf '%s ' "$1" > /dev/tty
        read -r reply < /dev/tty || reply=""
        echo "${reply:-$2}"
    else
        echo "$2"
    fi
}

os=$(uname -s)
case "$os" in
    Linux | Darwin) ;;
    *) die "unsupported OS: $os (on Windows, run this inside WSL)" ;;
esac

# --- rust -------------------------------------------------------------------

if ! command -v cargo > /dev/null 2>&1 && [ -x "$HOME/.cargo/bin/cargo" ]; then
    PATH="$HOME/.cargo/bin:$PATH"
fi
if ! command -v cargo > /dev/null 2>&1; then
    answer=$(ask "Rust isn't installed. Install it with rustup now? [Y/n]" y)
    case "$answer" in
        [nN]*) die "wooma needs Rust to build: https://rustup.rs" ;;
    esac
    command -v curl > /dev/null 2>&1 || die "curl is required to install Rust"
    info "installing Rust"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
    PATH="$HOME/.cargo/bin:$PATH"
fi

# ring (used for TLS) compiles a little C.
if [ "$os" = Linux ] && ! command -v cc > /dev/null 2>&1; then
    die "a C compiler is required. Install one first, e.g.
    Debian/Ubuntu: sudo apt install build-essential
    Fedora:        sudo dnf install gcc
    Arch:          sudo pacman -S base-devel"
fi

# --- build ------------------------------------------------------------------

info "building wooma (takes a minute or two)"
# Cargo's built-in git can't follow some git configs (e.g. an insteadOf rule
# that rewrites https://github.com/ to ssh), so use the system git when present.
if command -v git > /dev/null 2>&1; then
    export CARGO_NET_GIT_FETCH_WITH_CLI=true
fi
cargo install --git "$REPO" --locked --force wooma

bin="${CARGO_HOME:-$HOME/.cargo}/bin/wooma"
[ -x "$bin" ] || die "build finished but $bin is missing"
info "installed $bin"

# --- ICMP permissions (Linux) -----------------------------------------------

icmp_ok() {
    # Raw sockets or an unprivileged ping socket both mean ping and trace work.
    "$bin" config 2>/dev/null | grep -q '^icmp: *\(raw\|unprivileged\)'
}

if [ "$os" = Linux ] && ! icmp_ok; then
    echo
    info "ping and traceroute need permission to send ICMP"
    echo "  1) allow unprivileged ping for all users (sysctl, survives reinstalls)"
    echo "  2) give just the wooma binary raw sockets (setcap, redo after each reinstall)"
    echo "  3) skip"
    if [ -n "${WOOMA_ICMP:-}" ]; then
        choice=$WOOMA_ICMP
    elif has_tty; then
        choice=$(ask "Choose [1]:" 1)
    else
        choice=skip
    fi

    case "$choice" in
        1 | sysctl)
            info "writing /etc/sysctl.d/99-wooma-ping.conf (needs sudo)"
            echo 'net.ipv4.ping_group_range = 0 2147483647' |
                sudo tee /etc/sysctl.d/99-wooma-ping.conf > /dev/null
            sudo sysctl -q -w net.ipv4.ping_group_range="0 2147483647"
            # Without systemd (older WSL setups) nothing re-applies sysctl.d at boot.
            if [ ! -d /run/systemd/system ]; then
                warn "systemd isn't running, so this may reset after a reboot or 'wsl --shutdown'.
         If it does, rerun this installer and pick option 2 instead."
            fi
            ;;
        2 | setcap)
            command -v setcap > /dev/null 2>&1 || die "setcap not found (Debian/Ubuntu: sudo apt install libcap2-bin)"
            info "granting cap_net_raw to $bin (needs sudo)"
            sudo setcap cap_net_raw+ep "$bin"
            ;;
        *)
            echo "skipped. See the Permissions section of the README to set this up later."
            ;;
    esac

    if icmp_ok; then
        info "ICMP access ok"
    elif [ "$choice" != skip ] && [ "$choice" != 3 ]; then
        warn "ICMP still isn't available; run 'wooma config' for details"
    fi
fi

# --- done -------------------------------------------------------------------

echo
case ":$USER_PATH:" in
    *":$(dirname "$bin"):"*) info "done. Run: wooma" ;;
    *) info "done. Open a new shell (or run: . \"\$HOME/.cargo/env\") and then run: wooma" ;;
esac
