#!/usr/bin/env bash
# neox-rs installer.
#
# Installs the latest published neox-rs release bundle from GitHub releases,
# verifying the bundle checksum. Linux bundles also include neox-dkg-prover.
#
# One-line install:
#   curl -fsSL https://raw.githubusercontent.com/r3e-network/neox-rs/neox/scripts/install.sh | bash
#
# With options:
#   curl -fsSL https://raw.githubusercontent.com/r3e-network/neox-rs/neox/scripts/install.sh \
#     | bash -s -- --version neox-v2.4.1-rc.6 --install-dir "$HOME/.neox-rs/bin"
#
# Environment overrides (flags take precedence):
#   NEOX_VERSION         release tag to install (default: latest published release)
#   NEOX_INSTALL_DIR     installation directory (default: $HOME/.neox-rs/bin)
#   NEOX_NO_MODIFY_PATH  set to 1 to skip shell profile PATH updates
#   NEOX_REPO            GitHub <owner>/<repo> to install from (default: r3e-network/neox-rs)
#
# The whole script body runs inside main(), invoked on the final line, so a
# truncated download through `curl | bash` executes nothing.

set -euo pipefail

REPO="${NEOX_REPO:-r3e-network/neox-rs}"
API_BASE="https://api.github.com/repos"
BINARIES=(neox-rs neox-dkg-migrate)

say() { printf 'neox-rs: %s\n' "$*"; }
warn() { printf 'neox-rs: warning: %s\n' "$*" >&2; }
err() {
    printf 'neox-rs: error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
neox-rs installer

Usage: install.sh [options]

Options:
  --version <tag>       Release tag to install, e.g. neox-v2.4.1-rc.6 (default: latest
                        published release)
  --install-dir <dir>   Installation directory (default: $HOME/.neox-rs/bin)
  --no-modify-path      Do not update shell profiles to add the install
                        directory to PATH
  -h, --help            Show this help

Environment variables NEOX_VERSION, NEOX_INSTALL_DIR, NEOX_NO_MODIFY_PATH, and
NEOX_REPO provide the same controls; command-line flags take precedence.

Supported platforms: Linux x86_64 (glibc), Linux aarch64 (glibc), and macOS
Apple Silicon. Build from source on other platforms:
https://github.com/r3e-network/neox-rs#build-and-run

Managed DKG validator operation and neox-dkg-prover are supported on Linux only.
The macOS bundle supports full-node operation and omits the prover helper.
EOF
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"
}

detect_target() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"
    case "$os" in
        Linux)
            if command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then
                err "musl-based Linux (e.g. Alpine) is not covered by the release binaries; build from source: https://github.com/r3e-network/neox-rs#build-and-run"
            fi
            case "$arch" in
                x86_64 | amd64) TARGET="x86_64-unknown-linux-gnu" ;;
                aarch64 | arm64) TARGET="aarch64-unknown-linux-gnu" ;;
                *) err "unsupported Linux architecture: $arch (release binaries cover x86_64 and aarch64)" ;;
            esac
            BINARIES+=(neox-dkg-prover)
            ;;
        Darwin)
            case "$arch" in
                arm64) TARGET="aarch64-apple-darwin" ;;
                x86_64)
                    # An x86_64 shell under Rosetta still runs on Apple Silicon
                    # hardware, where the native aarch64 bundle works.
                    if [ "$(sysctl -in hw.optional.arm64 2>/dev/null || true)" = "1" ]; then
                        TARGET="aarch64-apple-darwin"
                    else
                        err "Intel macOS is not covered by the release binaries (Apple Silicon only); build from source: https://github.com/r3e-network/neox-rs#build-and-run"
                    fi
                    ;;
                *) err "unsupported macOS architecture: $arch" ;;
            esac
            ;;
        *)
            err "unsupported operating system: $os (release binaries cover Linux and macOS)"
            ;;
    esac
}

# Fetches a GitHub API URL without failing on HTTP errors; the caller inspects
# API_STATUS (HTTP code, or 0 on a transport failure) and API_BODY. `curl -f`
# would discard error bodies, hiding rate-limit responses and turning 404s for
# unpublished (draft) tags into misleading generic failures.
github_api() {
    local url="$1" raw
    if ! raw="$(curl -sSL --proto '=https' --tlsv1.2 --retry 3 \
        -H 'Accept: application/vnd.github+json' \
        -w '\n%{http_code}' "$url")"; then
        API_STATUS=0
        API_BODY=""
        return
    fi
    API_STATUS="${raw##*$'\n'}"
    API_BODY="${raw%$'\n'*}"
}

api_fail() {
    local url="$1"
    if [ "$API_STATUS" = "403" ] || [ "$API_STATUS" = "429" ]; then
        if printf '%s' "$API_BODY" | grep -q 'rate limit'; then
            err "GitHub API rate limit exceeded; retry later or download a bundle manually from https://github.com/$REPO/releases"
        fi
    fi
    if [ "$API_STATUS" = "0" ]; then
        err "GitHub API request failed: $url (check network connectivity)"
    fi
    err "GitHub API request failed with HTTP $API_STATUS: $url"
}

extract_first_tag() {
    grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"neox-v[^"]+"' |
        head -n 1 | grep -oE 'neox-v[^"]+'
}

resolve_tag() {
    if [ -n "$VERSION" ]; then
        TAG="$VERSION"
        return
    fi
    say "resolving the latest release of $REPO"
    # /releases/latest excludes prereleases by GitHub semantics; a 404 means no
    # stable release has been published yet.
    github_api "$API_BASE/$REPO/releases/latest"
    if [ "$API_STATUS" = "200" ]; then
        TAG="$(printf '%s' "$API_BODY" | extract_first_tag)" || true
        if [ -n "${TAG:-}" ]; then
            return
        fi
    elif [ "$API_STATUS" != "404" ]; then
        api_fail "$API_BASE/$REPO/releases/latest"
    fi
    github_api "$API_BASE/$REPO/releases?per_page=30"
    [ "$API_STATUS" = "200" ] || api_fail "$API_BASE/$REPO/releases?per_page=30"
    TAG="$(printf '%s' "$API_BODY" | extract_first_tag)" || true
    if [ -z "${TAG:-}" ]; then
        err "no published neox-rs release found at https://github.com/$REPO/releases (draft releases are not downloadable); pass --version <tag> once a release is published"
    fi
    warn "no stable release is published yet; installing prerelease $TAG"
}

resolve_asset_urls() {
    say "locating the $TARGET bundle for $TAG"
    github_api "$API_BASE/$REPO/releases/tags/$TAG"
    if [ "$API_STATUS" = "404" ]; then
        err "release $TAG is not published (draft releases are not downloadable) or does not exist; see https://github.com/$REPO/releases"
    fi
    [ "$API_STATUS" = "200" ] || api_fail "$API_BASE/$REPO/releases/tags/$TAG"
    local urls
    urls="$(printf '%s' "$API_BODY" |
        grep -oE '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]+"' |
        grep -oE 'https://[^"]+')" || true
    TARBALL_URL="$(printf '%s\n' "$urls" | grep -E -- "-$TARGET\.tar\.gz$" | head -n 1)" || true
    SHA_URL="$(printf '%s\n' "$urls" | grep -E -- "-$TARGET\.tar\.gz\.sha256$" | head -n 1)" || true
    if [ -z "${TARBALL_URL:-}" ] || [ -z "${SHA_URL:-}" ]; then
        err "release $TAG has no bundle for $TARGET; available assets: https://github.com/$REPO/releases/tag/$TAG"
    fi
}

download() {
    local url="$1" dest="$2"
    say "downloading ${url##*/}"
    curl -fL --proto '=https' --tlsv1.2 --retry 3 --progress-bar -o "$dest" "$url" ||
        err "download failed: $url"
}

verify_checksum() {
    local dir="$1" sha_file="$2"
    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$dir" && sha256sum --check --strict "$sha_file" >/dev/null) ||
            err "checksum verification failed for ${sha_file%.sha256}"
    elif command -v shasum >/dev/null 2>&1; then
        (cd "$dir" && shasum -a 256 --check --strict "$sha_file" >/dev/null) ||
            err "checksum verification failed for ${sha_file%.sha256}"
    else
        err "neither sha256sum nor shasum is available; refusing to install unverified binaries"
    fi
    say "checksum verified"
}

install_bundle() {
    local tmpdir="$1" tarball_name="$2"
    local bundle="${tarball_name%.tar.gz}"
    tar -xzf "$tmpdir/$tarball_name" -C "$tmpdir" ||
        err "failed to extract $tarball_name"
    [ -d "$tmpdir/$bundle" ] || err "bundle directory $bundle missing from the archive"
    # Validate the whole bundle before installing anything, so a bad archive
    # cannot leave a partial mix of old and new binaries behind.
    local binary
    for binary in "${BINARIES[@]}"; do
        [ -f "$tmpdir/$bundle/$binary" ] || err "binary $binary missing from the bundle"
    done
    mkdir -p "$INSTALL_DIR" || err "cannot create install directory: $INSTALL_DIR"
    for binary in "${BINARIES[@]}"; do
        install -m 755 "$tmpdir/$bundle/$binary" "$INSTALL_DIR/$binary" ||
            err "failed to install $binary into $INSTALL_DIR"
    done
    say "installed ${BINARIES[*]} into $INSTALL_DIR"
}

profile_file() {
    local shell_name
    shell_name="$(basename "${SHELL:-sh}")"
    case "$shell_name" in
        zsh) printf '%s' "${ZDOTDIR:-$HOME}/.zshenv" ;;
        bash) printf '%s' "$HOME/.bashrc" ;;
        *) printf '%s' "$HOME/.profile" ;;
    esac
}

update_path() {
    case ":$PATH:" in
        *":$INSTALL_DIR:"*)
            return
            ;;
    esac
    # Single-quote the directory in the profile line so spaces and shell
    # metacharacters in the path survive; embedded single quotes become '\''.
    local quoted_dir export_line
    quoted_dir="'${INSTALL_DIR//\'/\'\\\'\'}'"
    export_line="export PATH=$quoted_dir:\"\$PATH\""
    if [ "$MODIFY_PATH" != "1" ] || [ -z "${HOME:-}" ]; then
        say "add the install directory to PATH to finish setup:"
        say "  $export_line"
        return
    fi
    case "$INSTALL_DIR" in
        *$'\n'*)
            warn "install directory contains a newline; refusing to edit shell profiles"
            say "add the install directory to PATH manually to finish setup"
            return
            ;;
    esac
    local profile
    profile="$(profile_file)"
    if [ -f "$profile" ] && grep -qF "$export_line" "$profile"; then
        say "PATH entry already present in $profile; restart your shell to pick it up"
        return
    fi
    {
        printf '\n# Added by the neox-rs installer\n'
        printf '%s\n' "$export_line"
    } >>"$profile" || err "failed to update $profile; add this line manually: $export_line"
    say "added $INSTALL_DIR to PATH in $profile"
    say "restart your shell or run: source \"$profile\""
}

parse_args() {
    VERSION="${NEOX_VERSION:-}"
    # The $HOME-based default is resolved lazily in main() so --help works and
    # a clean error is produced when HOME is unset under `set -u`.
    INSTALL_DIR="${NEOX_INSTALL_DIR:-}"
    MODIFY_PATH=1
    if [ "${NEOX_NO_MODIFY_PATH:-0}" = "1" ]; then
        MODIFY_PATH=0
    fi
    while [ $# -gt 0 ]; do
        case "$1" in
            --version)
                [ $# -ge 2 ] || err "--version requires a release tag argument"
                VERSION="$2"
                shift 2
                ;;
            --install-dir)
                [ $# -ge 2 ] || err "--install-dir requires a directory argument"
                INSTALL_DIR="$2"
                shift 2
                ;;
            --no-modify-path)
                MODIFY_PATH=0
                shift
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            *)
                err "unknown option: $1 (run with --help for usage)"
                ;;
        esac
    done
}

main() {
    parse_args "$@"
    if [ -z "$INSTALL_DIR" ]; then
        [ -n "${HOME:-}" ] || err "HOME is not set; pass --install-dir <dir>"
        INSTALL_DIR="$HOME/.neox-rs/bin"
    fi
    need_cmd curl
    need_cmd tar
    need_cmd uname
    need_cmd mktemp
    need_cmd install
    detect_target
    say "target platform: $TARGET"
    resolve_tag
    say "installing release $TAG"
    resolve_asset_urls

    # Deliberately not `local`: the EXIT trap fires after main() returns, when
    # locals are out of scope and `set -u` would abort the trap itself.
    TMP_DIR="$(mktemp -d)" || err "failed to create a temporary directory"
    trap 'rm -rf "${TMP_DIR:-}"' EXIT

    local tarball_name sha_name
    tarball_name="${TARBALL_URL##*/}"
    sha_name="${SHA_URL##*/}"
    download "$TARBALL_URL" "$TMP_DIR/$tarball_name"
    download "$SHA_URL" "$TMP_DIR/$sha_name"
    verify_checksum "$TMP_DIR" "$sha_name"
    install_bundle "$TMP_DIR" "$tarball_name"
    update_path

    # Captured via assignment so a non-running binary (e.g. wrong architecture)
    # fails the install instead of vanishing inside an argument substitution.
    local installed_version
    installed_version="$("$INSTALL_DIR/neox-rs" --version | head -n 1)" ||
        err "the installed neox-rs binary failed to run; the platform may not match the bundle"
    say "installed version: $installed_version"
    say "run a MainNet full node with: neox-rs node --chain neox-mainnet --http"
}

main "$@"
