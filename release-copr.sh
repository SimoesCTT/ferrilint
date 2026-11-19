#!/usr/bin/env bash
set -e

VERSION=$(grep -m 1 'version' Cargo.toml | cut -d '"' -f 2)
NAME="ferrilint"
ARCHIVE_NAME="${NAME}-${VERSION}.tar.gz"
SRPM_PATH="$HOME/rpmbuild/SRPMS/${NAME}-${VERSION}-1.fc45.src.rpm"
DESCRIPTION="Lightning-fast, zero-FFI pure-Rust static analysis engine and inspection suite for .spec files, source RPMs (.src.rpm), and binary RPMs (.rpm)."

echo -e "\033[1;32m[1/4]\033[0m Archiving git repository for v${VERSION}..."
mkdir -p "$HOME/rpmbuild/SOURCES"
git archive --format=tar.gz --prefix="${NAME}-${VERSION}/" HEAD > "$HOME/rpmbuild/SOURCES/${ARCHIVE_NAME}"

echo -e "\033[1;32m[2/4]\033[0m Building Source RPM (SRPM)..."
rpmbuild -bs "${NAME}.spec"

echo -e "\033[1;32m[3/4]\033[0m Ensuring Fedora Copr project exists..."
copr-cli create "${NAME}" --chroot fedora-45-x86_64 --description "${DESCRIPTION}" 2>/dev/null || echo "Project already exists, proceeding..."

echo -e "\033[1;32m[4/4]\033[0m Submitting SRPM to Fedora Copr..."
copr-cli build --nowait "${NAME}" "${SRPM_PATH}"

echo -e "\n\033[1;32m[SUCCESS]\033[0m ferrilint v${VERSION} submitted to Copr!"
