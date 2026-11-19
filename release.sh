#!/usr/bin/env bash
# Safe release script: runs without killing the parent interactive shell on error

main() {
    set -uo pipefail

    PKG_NAME="ferrilint"
    VERSION="0.1.0"
    DIST_DIR="$(pwd)"

    echo "==> Cleaning old build artifacts..."
    rm -rf vendor "${PKG_NAME}-*vendor.tar.xz" v0.1.0.tar.gz "${PKG_NAME}-*.src.rpm" "${PKG_NAME}-*.tar.gz"

    echo "==> Creating git archive..."
    if ! git archive --format=tar.gz --prefix="${PKG_NAME}-${VERSION}/" -o "${PKG_NAME}-${VERSION}.tar.gz" HEAD; then
        echo "ERROR: Git archive failed." >&2
        return 1
    fi

    echo "==> Generating vendor archive..."
    if ! cargo vendor vendor; then
        echo "ERROR: cargo vendor failed." >&2
        rm -rf vendor
        return 1
    fi

    if ! tar caf "${PKG_NAME}-${VERSION}-vendor.tar.xz" vendor; then
        echo "ERROR: Failed to compress vendor directory." >&2
        rm -rf vendor
        return 1
    fi
    rm -rf vendor

    echo "==> Building SRPM..."
    if ! rpmbuild -bs --define "_sourcedir ${DIST_DIR}" --define "_specdir ${DIST_DIR}" --define "_srcrpmdir ${DIST_DIR}" "${PKG_NAME}.spec"; then
        echo "ERROR: rpmbuild failed." >&2
        return 1
    fi

    echo "==> Verifying SRPM contents..."
    SRPM_FILE=$(ls ${PKG_NAME}-${VERSION}-1.*.src.rpm 2>/dev/null | head -n 1)
    if [ -z "${SRPM_FILE}" ]; then
        echo "ERROR: SRPM file not found." >&2
        return 1
    fi

    if ! rpm -qpl "${SRPM_FILE}" | grep -q "vendor.tar.xz"; then
        echo "ERROR: Vendor tarball missing from SRPM!" >&2
        return 1
    fi

    echo "==> Submitting to Copr..."
    if ! copr-cli build "${PKG_NAME}" "${SRPM_FILE}"; then
        echo "ERROR: Copr submission failed." >&2
        return 1
    fi

    echo "==> Success! Package submitted to Copr."
}

# Run inside a subshell wrapper to completely isolate execution and protect the active terminal
(main)
