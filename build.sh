#!/usr/bin/env bash
#
# Convenience wrapper around the CMake superbuild.
#
#   TOOLCHAIN_ROOT=/path/to/arm-linux-gnueabihf-toolchain ./build.sh
#
# Optional env:
#   BUILD_DIR     (default: build)
#   BUILD_TYPE    (default: Release)
#   CROSS_COMPILE (default: arm-linux-gnueabihf-)
#   JOBS          (default: nproc)
#
set -euo pipefail

ROOT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
JOBS="${JOBS:-$(nproc)}"

if [[ -z "${TOOLCHAIN_ROOT:-}" ]]; then
    echo "ERROR: TOOLCHAIN_ROOT is not set." >&2
    echo "  export TOOLCHAIN_ROOT=/path/to/gcc-...-arm-linux-gnueabihf" >&2
    exit 1
fi

echo "==> Root:       ${ROOT_DIR}"
echo "==> Toolchain:  ${TOOLCHAIN_ROOT}"
echo "==> Build dir:  ${BUILD_DIR}"
echo "==> Build type: ${BUILD_TYPE}"
echo "==> Jobs:       ${JOBS}"


cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" \
    -DCMAKE_TOOLCHAIN_FILE="${ROOT_DIR}/armhf-toolchain.cmake" \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" -DSE05X_STRIP=ON

cmake --build "${BUILD_DIR}" -j"${JOBS}"

echo "==> Done. Artifacts in: ${BUILD_DIR}/stage"
