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

    if [[ -n "${KSU_MANAGER_PACKAGE:-}" ]]; then
        make_args+=("KSU_MANAGER_PACKAGE=$KSU_MANAGER_PACKAGE")
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
