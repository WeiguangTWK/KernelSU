#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"

usage() {
    cat <<'EOF'
Initialize the Kernel audit-provenance RSA-3072 trust anchor.

Usage:
  init-provenance-certificate.sh --output-dir ABSOLUTE_PATH [options]

Options:
  --output-dir PATH       New directory outside the source tree (required)
  --security-epoch N      Minimum accepted security epoch (default: 1)
  --common-name NAME      X.509 common name
  --validity-days N       Certificate validity for build records (default: 3650)
  -h, --help              Show this help

The private key never enters the source tree. The generated build.env exports
only public build inputs; it does not export the private-key path.
EOF
}

require_command() {
    local command_name="$1"

    command -v "$command_name" >/dev/null 2>&1 || {
        echo "Error: required command not found: $command_name" >&2
        exit 127
    }
}

output_dir=""
security_epoch="1"
common_name="AegisSU production provenance"
validity_days="3650"

while (( $# > 0 )); do
    case "$1" in
        --output-dir)
            (( $# >= 2 )) || { echo "Error: --output-dir requires a value" >&2; exit 2; }
            output_dir="$2"
            shift 2
            ;;
        --security-epoch)
            (( $# >= 2 )) || { echo "Error: --security-epoch requires a value" >&2; exit 2; }
            security_epoch="$2"
            shift 2
            ;;
        --common-name)
            (( $# >= 2 )) || { echo "Error: --common-name requires a value" >&2; exit 2; }
            common_name="$2"
            shift 2
            ;;
        --validity-days)
            (( $# >= 2 )) || { echo "Error: --validity-days requires a value" >&2; exit 2; }
            validity_days="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

[[ -n "$output_dir" ]] || { echo "Error: --output-dir is required" >&2; exit 2; }
[[ "$output_dir" == /* ]] || { echo "Error: --output-dir must be absolute" >&2; exit 2; }
[[ "$security_epoch" =~ ^[1-9][0-9]*$ ]] || {
    echo "Error: --security-epoch must be a positive integer" >&2
    exit 2
}
[[ "$validity_days" =~ ^[1-9][0-9]*$ ]] || {
    echo "Error: --validity-days must be a positive integer" >&2
    exit 2
}
[[ -n "$common_name" && "$common_name" != *$'\n'* && "$common_name" != *$'\r'* ]] || {
    echo "Error: --common-name must be a nonempty single line" >&2
    exit 2
}

require_command cargo
require_command openssl
require_command realpath
require_command sha256sum

output_dir="$(realpath -m -- "$output_dir")"
case "$output_dir/" in
    "$REPO_ROOT/"*)
        echo "Error: provenance private material must be outside the source tree" >&2
        exit 2
        ;;
esac
[[ ! -e "$output_dir" ]] || {
    echo "Error: refusing to overwrite existing path: $output_dir" >&2
    exit 2
}

output_parent="$(dirname -- "$output_dir")"
mkdir -p -- "$output_parent"
staging_dir="$(mktemp -d -- "$output_parent/.aegissu-provenance.XXXXXXXX")"
completed=false
cleanup() {
    if [[ "$completed" != true && -n "${staging_dir:-}" && -d "$staging_dir" ]]; then
        rm -rf -- "$staging_dir"
    fi
}
trap cleanup EXIT
umask 077

private_key="$staging_dir/provenance-private-key.pem"
certificate_pem="$staging_dir/provenance-certificate.pem"
certificate_der="$staging_dir/provenance-certificate.der"
public_header="$staging_dir/provenance-public-key.h"

echo "=== Generate RSA-3072 provenance certificate ==="
cargo run --quiet --release \
    --manifest-path "$REPO_ROOT/userspace/ksud/Cargo.toml" \
    -- provenance-manifest generate-certificate \
    --private-key "$private_key" \
    --certificate "$certificate_pem" \
    --common-name "$common_name" \
    --validity-days "$validity_days"

openssl x509 -in "$certificate_pem" -outform DER -out "$certificate_der"
certificate_key_id="$(sha256sum "$certificate_der")"
certificate_key_id="${certificate_key_id%% *}"

echo "=== Emit public-only kernel header ==="
cargo run --quiet --release \
    --manifest-path "$REPO_ROOT/userspace/ksud/Cargo.toml" \
    -- provenance-manifest emit-kernel-key-header \
    --current-certificate "$certificate_pem" \
    --current-private-key "$private_key" \
    --current-minimum-epoch "$security_epoch" \
    --output "$public_header"

final_header="$output_dir/provenance-public-key.h"
final_certificate="$output_dir/provenance-certificate.pem"
{
    printf 'export CONFIG_KSU_PROVENANCE=y\n'
    printf 'export KSU_PROVENANCE_KEY_HEADER=%q\n' "$final_header"
    printf 'export KSU_PROVENANCE_SECURITY_EPOCH=%q\n' "$security_epoch"
    printf 'export KSU_PROVENANCE_CERTIFICATE=%q\n' "$final_certificate"
    printf 'export KSU_PROVENANCE_CERTIFICATE_KEY_ID=%q\n' "$certificate_key_id"
} >"$staging_dir/build.env"

{
    printf 'format_version=1\n'
    printf 'key_header_format=2\n'
    printf 'algorithm=RSA-3072-PKCS1-v1_5-SHA256\n'
    printf 'security_epoch=%s\n' "$security_epoch"
    printf 'certificate_key_id=%s\n' "$certificate_key_id"
    printf 'private_key_file=provenance-private-key.pem\n'
    printf 'certificate_pem_file=provenance-certificate.pem\n'
    printf 'certificate_der_file=provenance-certificate.der\n'
    printf 'public_header_file=provenance-public-key.h\n'
} >"$staging_dir/metadata.txt"

chmod 600 "$private_key"
chmod 644 "$certificate_pem" "$certificate_der" "$public_header" \
    "$staging_dir/build.env" "$staging_dir/metadata.txt"
mv -T -n -- "$staging_dir" "$output_dir"
if [[ -d "$staging_dir" ]]; then
    echo "Error: output path appeared during initialization: $output_dir" >&2
    exit 2
fi
completed=true
trap - EXIT

echo
echo "Kernel provenance certificate initialized."
echo "Output directory : $output_dir"
echo "Certificate ID   : $certificate_key_id"
echo "Security epoch   : $security_epoch"
echo "Public header    : $final_header"
echo "Private key      : $output_dir/provenance-private-key.pem"
echo
echo "Before kernel/build-all.sh, run:"
printf '  source %q\n' "$output_dir/build.env"
