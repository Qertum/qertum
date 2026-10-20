#!/usr/bin/env bash
#
# Restore a Qertum /data volume from an archive produced by backup.sh.
#
# The target container must already exist (create it once with
# `docker compose up` first) — this script stops it, replaces the contents of
# /data, and restarts it.
#
# Usage: ./restore.sh <archive.tar.gz> [container-name]
set -euo pipefail

ARCHIVE="${1:?usage: restore.sh <archive.tar.gz> [container-name]}"
CONTAINER="${2:-qertum}"

if [ ! -f "${ARCHIVE}" ]; then
  echo "error: archive not found: ${ARCHIVE}" >&2
  exit 1
fi

if ! docker inspect "${CONTAINER}" >/dev/null 2>&1; then
  echo "error: container '${CONTAINER}' not found — create it once with 'docker compose up' first" >&2
  exit 1
fi

echo "WARNING: this replaces the current contents of /data in '${CONTAINER}' with ${ARCHIVE}."
read -r -p "Continue? [y/N] " confirm
if [ "${confirm}" != "y" ] && [ "${confirm}" != "Y" ]; then
  echo "Aborted."
  exit 1
fi

was_running=false
if [ "$(docker inspect -f '{{.State.Running}}' "${CONTAINER}")" = "true" ]; then
  was_running=true
  echo "Stopping ${CONTAINER}..."
  docker stop "${CONTAINER}" >/dev/null
fi

# /data/recovery holds this host's own backup records. An archive carries the copy from before it was
# taken, so it must neither be cleared nor overwritten by the extraction.
echo "Clearing existing /data (keeping /data/recovery)..."
docker run --rm --volumes-from "${CONTAINER}" alpine sh -c 'find /data -mindepth 1 -maxdepth 1 ! -name recovery -exec rm -rf {} + 2>/dev/null || true'

echo "Restoring ${ARCHIVE} -> /data in ${CONTAINER}"
docker run --rm \
  --volumes-from "${CONTAINER}" \
  -v "$(cd "$(dirname "${ARCHIVE}")" && pwd)":/backup \
  alpine tar xzf "/backup/$(basename "${ARCHIVE}")" -C / --exclude=data/recovery --exclude='data/recovery/*'

# Record that a restore was performed. It is not a verification: restoring into the live container
# proves nothing about signing or key access. See backup.sh for why the helper avoids double quotes.
COMPLETED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ARCHIVE_NAME="$(printf '%s' "$(basename "${ARCHIVE}")" | tr -c 'A-Za-z0-9._-' '_')"
docker run --rm --volumes-from "${CONTAINER}" \
  -e COMPLETED="${COMPLETED_AT}" -e ARCHIVE="${ARCHIVE_NAME}" -e BY="restore.sh" \
  alpine sh -c 'set -e; mkdir -p /data/recovery; chmod 755 /data/recovery; printf '"'"'{\042schemaVersion\042:1,\042kind\042:\042performed\042,\042completedAtUtc\042:\042%s\042,\042archiveName\042:\042%s\042,\042reportedBy\042:\042%s\042}\n'"'"' $COMPLETED $ARCHIVE $BY > /data/recovery/last-restore.json.tmp; chmod 644 /data/recovery/last-restore.json.tmp; mv /data/recovery/last-restore.json.tmp /data/recovery/last-restore.json' \
  || echo "warning: the restore worked, but its status could not be recorded for the Qertum dashboard" >&2

if [ "${was_running}" = true ]; then
  echo "Starting ${CONTAINER}..."
  docker start "${CONTAINER}" >/dev/null
fi

echo "Restore complete."
