#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DEFAULT_KMIS=(
    android12-5.10
    android13-5.10
    android13-5.15
    android14-5.15
    android14-6.1
    android15-6.6
    android16-6.12
)

if (( $# > 0 )); then
    KMIS=("$@")
else
    KMIS=("${DEFAULT_KMIS[@]}")
fi

: "${KSU_EXPECTED_SIZE:?Please export KSU_EXPECTED_SIZE}"
: "${KSU_EXPECTED_HASH:?Please export KSU_EXPECTED_HASH}"
: "${KSU_MANAGER_PACKAGE:?Please export KSU_MANAGER_PACKAGE}"

if [[ ! "$KSU_EXPECTED_SIZE" =~ ^(0[xX][0-9a-fA-F]+|0|[1-9][0-9]*)$ ]]; then
    echo "Error: KSU_EXPECTED_SIZE must be a hexadecimal or decimal integer" >&2
    exit 2
fi
if [[ ! "$KSU_EXPECTED_HASH" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "Error: KSU_EXPECTED_HASH must contain exactly 64 hexadecimal characters" >&2
    exit 2
fi
if [[ ! "$KSU_MANAGER_PACKAGE" =~ ^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$ ]]; then
    echo "Error: KSU_MANAGER_PACKAGE is not a valid Android package name" >&2
    exit 2
fi

KSU_MANAGER_CERT_MAX_LENGTH="$({
    sed -n 's/^#define KSU_MANAGER_CERT_MAX_LENGTH \([0-9][0-9]*\)$/\1/p' manager/apk_sign.h || true
} | head -n 1)"
if [[ ! "$KSU_MANAGER_CERT_MAX_LENGTH" =~ ^[0-9]+$ ]]; then
    echo "Error: unable to read KSU_MANAGER_CERT_MAX_LENGTH" >&2
    exit 2
fi
if (( KSU_EXPECTED_SIZE == 0 || KSU_EXPECTED_SIZE > KSU_MANAGER_CERT_MAX_LENGTH )); then
    echo "Error: KSU_EXPECTED_SIZE must be between 1 and $KSU_MANAGER_CERT_MAX_LENGTH bytes" >&2
    exit 2
fi

KSU_PROVENANCE_BUILD="${CONFIG_KSU_PROVENANCE:-n}"
case "$KSU_PROVENANCE_BUILD" in
    y)
        : "${KSU_PROVENANCE_KEY_HEADER:?Please export KSU_PROVENANCE_KEY_HEADER when CONFIG_KSU_PROVENANCE=y}"
        if [[ "$KSU_PROVENANCE_KEY_HEADER" != /* ]]; then
            echo "Error: KSU_PROVENANCE_KEY_HEADER must be an absolute path" >&2
            exit 2
        fi
        if [[ ! -f "$KSU_PROVENANCE_KEY_HEADER" || ! -r "$KSU_PROVENANCE_KEY_HEADER" ]]; then
            echo "Error: provenance public key header is not a readable regular file: $KSU_PROVENANCE_KEY_HEADER" >&2
            exit 2
        fi
        ;;
    n)
        if [[ -n "${KSU_PROVENANCE_KEY_HEADER:-}" ]]; then
            echo "Error: KSU_PROVENANCE_KEY_HEADER is set but CONFIG_KSU_PROVENANCE is not y" >&2
            exit 2
        fi
        ;;
    *)
        echo "Error: CONFIG_KSU_PROVENANCE must be y or n" >&2
        exit 2
        ;;
esac

DDK_BIN="${DDK_BIN:-ddk}"
DDK_ROOT="${DDK_ROOT:-/opt/ddk}"
OUTPUT_DIR="$SCRIPT_DIR/out"
DIST_DIR="$SCRIPT_DIR/dist"

command -v "$DDK_BIN" >/dev/null 2>&1 || {
    echo "Error: ddk command not found" >&2
    exit 127
}

command -v llvm-strip >/dev/null 2>&1 || {
    echo "Error: llvm-strip command not found" >&2
    exit 127
}

mkdir -p "$OUTPUT_DIR" "$DIST_DIR"

success=()
failed=()

for kmi in "${KMIS[@]}"; do
    echo "========== Building $kmi =========="

    # Android 16 / 6.12 Kbuild resolves C prerequisites from $(obj), so its
    # external module source and output directories cannot be separated using
    # the src= workaround used by older kernels.
    if [[ "$kmi" == "android16-6.12" ]]; then
        kmi_output="$SCRIPT_DIR"

        kdir_config="$DDK_ROOT/kdir/$kmi/.config"
        expected_pahole_version=""
        if [[ -f "$kdir_config" ]]; then
            expected_pahole_version="$({
                sed -n 's/^CONFIG_PAHOLE_VERSION=//p' "$kdir_config" || true
            } | head -n 1)"
        fi

        if [[ -n "$expected_pahole_version" ]]; then
            if ! command -v pahole >/dev/null 2>&1; then
                echo "Error: pahole is required for $kmi (expected version $expected_pahole_version)" >&2
                failed+=("$kmi")
                echo
                continue
            fi

            if ! actual_pahole_version="$(pahole --numeric_version 2>/dev/null)" ||
                [[ ! "$actual_pahole_version" =~ ^[0-9]+$ ]]; then
                echo "Error: unable to determine pahole version" >&2
                failed+=("$kmi")
                echo
                continue
            fi

            if (( actual_pahole_version < expected_pahole_version )); then
                echo "Error: $kmi KDIR expects pahole $expected_pahole_version, but Host has $actual_pahole_version" >&2
                failed+=("$kmi")
                echo
                continue
            fi

            echo "Using pahole $actual_pahole_version (KDIR expects $expected_pahole_version)"
        fi
    else
        kmi_output="$OUTPUT_DIR/$kmi"
    fi

    final_module="$DIST_DIR/${kmi}_kernelsu.ko"

    make_args=(
        "ODIR=$kmi_output"
        "CONFIG_KSU=m"
        "KSU_EXPECTED_SIZE=$KSU_EXPECTED_SIZE"
        "KSU_EXPECTED_HASH=$KSU_EXPECTED_HASH"
    )

    make_args+=("KSU_MANAGER_PACKAGE=$KSU_MANAGER_PACKAGE")

    if [[ "$KSU_PROVENANCE_BUILD" == "y" ]]; then
        make_args+=(
            "CONFIG_KSU_PROVENANCE=y"
            "KSU_PROVENANCE_KEY_HEADER=$KSU_PROVENANCE_KEY_HEADER"
        )
    fi

    if "$DDK_BIN" build --target "$kmi" -- "${make_args[@]}"; then
        built_module="$kmi_output/kernelsu.ko"

        if [[ ! -f "$built_module" ]]; then
            echo "Error: expected output not found: $built_module" >&2
            failed+=("$kmi")
            continue
        fi

        cp -f "$built_module" "$final_module"
        llvm-strip -d "$final_module"

        echo "Built: $final_module"
        success+=("$kmi")
    else
        echo "Build failed: $kmi" >&2
        failed+=("$kmi")
    fi

    echo
done

echo "========== Build summary =========="

if (( ${#success[@]} > 0 )); then
    printf 'Successful: %s\n' "${success[*]}"
fi

if (( ${#failed[@]} > 0 )); then
    printf 'Failed: %s\n' "${failed[*]}" >&2
    exit 1
fi

ls -lh "$DIST_DIR"/*_kernelsu.ko
