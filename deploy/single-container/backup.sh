#!/usr/bin/env bash
#
# Backup the Qertum /data volume (CA key, shared DB, Data Protection keyring,
# audit logs, IDM store) to a single timestamped tar.gz.
#
# SQLite and the CA files are not safe to tar while being written, so this stops
# the container for the duration of the archive, then restarts it. Runs against
# any container created from deploy/single-container (bind mount or named volume)
# via `docker run --volumes-from`, so it doesn't need to know the host path.
#
# It also writes <archive>.manifest (see manifest.sh) so restore-test.sh can prove the archive is a faithful copy.
#
# Usage: ./backup.sh [output-dir] [container-name]
set -euo pipefail

OUT_DIR="${1:-.}"
CONTAINER="${2:-qertum}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "${OUT_DIR}"
ARCHIVE_NAME="qertum-backup-${TIMESTAMP}.tar.gz"

if ! docker inspect "${CONTAINER}" >/dev/null 2>&1; then
  echo "error: container '${CONTAINER}' not found" >&2
  exit 1
fi

was_running=false
if [ "$(docker inspect -f '{{.State.Running}}' "${CONTAINER}")" = "true" ]; then
  was_running=true
  echo "Stopping ${CONTAINER} for a consistent backup..."
  docker stop "${CONTAINER}" >/dev/null
fi

cleanup() {
  if [ "${was_running}" = true ]; then
    echo "Restarting ${CONTAINER}..."
    docker start "${CONTAINER}" >/dev/null
  fi
}
trap cleanup EXIT

# A manifest of /data for restore-test.sh. The container is stopped, so /data is static and the manifest
# matches the archive taken next. It is read from the live volume, never from the archive, so a damaged
# archive cannot vouch for itself. A failure only warns: the archive is still good, it just cannot be verified.
MANIFEST_NAME="${ARCHIVE_NAME%.tar.gz}.manifest"
echo "Writing integrity manifest ${OUT_DIR}/${MANIFEST_NAME}"
if docker run --rm --volumes-from "${CONTAINER}" \
     -v "${SCRIPT_DIR}/manifest.sh":/manifest.sh:ro \
     alpine sh /manifest.sh > "${OUT_DIR}/${MANIFEST_NAME}.tmp"; then
  mv "${OUT_DIR}/${MANIFEST_NAME}.tmp" "${OUT_DIR}/${MANIFEST_NAME}"
else
  rm -f "${OUT_DIR}/${MANIFEST_NAME}.tmp"
  echo "warning: the backup continues, but no integrity manifest could be written, so restore-test.sh cannot verify it" >&2
fi

echo "Archiving /data from ${CONTAINER} -> ${OUT_DIR}/${ARCHIVE_NAME}"
docker run --rm \
  --volumes-from "${CONTAINER}" \
  -v "$(cd "${OUT_DIR}" && pwd)":/backup \
  alpine tar czf "/backup/${ARCHIVE_NAME}" -C / data

# Tell Qertum's dashboard when this backup finished. The container is stopped, so the data volume is
# written through the same helper image. A failure here only warns: the archive itself is fine.
# The helper script avoids double quotes (\042) so backup.ps1 can share it, and every value is limited
# to [A-Za-z0-9._:-], so none needs quoting.
SIZE_BYTES="$(wc -c < "${OUT_DIR}/${ARCHIVE_NAME}" | tr -d ' ')"
COMPLETED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
docker run --rm --volumes-from "${CONTAINER}" \
  -e COMPLETED="${COMPLETED_AT}" -e ARCHIVE="${ARCHIVE_NAME}" -e SIZE="${SIZE_BYTES}" -e BY="backup.sh" \
  alpine sh -c 'set -e; mkdir -p /data/recovery; chmod 755 /data/recovery; printf '"'"'{\042schemaVersion\042:1,\042completedAtUtc\042:\042%s\042,\042archiveName\042:\042%s\042,\042sizeBytes\042:%s,\042reportedBy\042:\042%s\042}\n'"'"' $COMPLETED $ARCHIVE $SIZE $BY > /data/recovery/last-backup.json.tmp; chmod 644 /data/recovery/last-backup.json.tmp; mv /data/recovery/last-backup.json.tmp /data/recovery/last-backup.json' \
  || echo "warning: the backup is fine, but its status could not be recorded for the Qertum dashboard" >&2

echo "Done: ${OUT_DIR}/${ARCHIVE_NAME} ($(du -h "${OUT_DIR}/${ARCHIVE_NAME}" | cut -f1))"
