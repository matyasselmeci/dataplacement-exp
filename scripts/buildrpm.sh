#!/bin/bash
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

SPEC=rpm/dataplacement.spec

NAME=$(rpmspec -q --srpm --qf '%{NAME}\n' "$SPEC")
VERSION=$(rpmspec -q --srpm --qf '%{VERSION}\n' "$SPEC")
SOURCE=$(rpmspec -q --srpm --qf '%{SOURCE}\n' "$SPEC")

TOPDIR="$(pwd)/.rpmbuild"
rm -rf "$TOPDIR"
mkdir -p "$TOPDIR"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

git archive \
    --format=tar.gz \
    --prefix="${NAME}-${VERSION}/" \
    -o "$TOPDIR/SOURCES/${SOURCE##*/}" \
    HEAD

rpmbuild -ba \
    --define "_topdir $TOPDIR" \
    "$SPEC"

cp -v "$TOPDIR"/RPMS/*/*.rpm .
cp -v "$TOPDIR"/SRPMS/*.rpm .

echo
echo "Built RPMs:"
ls -1 ./*.rpm
