#!/usr/bin/env bash
#
# Verify a backup archive of the multi-container deployment against its manifest. Stops nothing:
# the single-container restore-test.sh extracts into a scratch volume and only records the result
# on the volume that qertum-apiservice mounts.
#
# Usage: ./restore-test.sh [--image <ref>] <archive.tar.gz | backup-dir>
# Exit:  0 identical and usable   1 mismatch, unextractable, or a failed check   2 could not test
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: restore-test.sh [--image <ref>] <archive.tar.gz | backup-dir>" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/../single-container/restore-test.sh" "$@" "qertum-apiservice"
