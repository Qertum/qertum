#!/usr/bin/env bash
#
# Prove that a backup archive restores to a CA that works, without touching the operating container.
#
# Step 1 (manifest): the archive is extracted into a scratch Docker volume, the same manifest.sh is run over
# it, and the result is compared with the manifest backup.sh wrote next to the archive. A pass means the
# archive holds exactly the files, bytes, modes and owners that were on /data at backup time. It is not tamper
# protection: anyone who can alter both the archive and its manifest can forge a pass.
#
# Step 2 (usability): the image of the operating container (or --image) runs Qertum.RestoreCheck over the
# scratch volume with the network off and no service started: it opens the database, decrypts a stored secret
# with the restored key ring, signs a probe with each online issuer and builds a CRL that lists every revoked
# certificate. A pass means the restored files work when read by this version of Qertum. It does not start the
# running stack (identity, API, web, queue, Redis).
#
# The result is written to /data/recovery/last-restore.json of the operating container (the dashboard reads it):
# "usable" when both steps passed, "verified" when only the manifest step ran (no image known), "failed" when
# either step failed. A run that could not test (exit 2) records nothing. The container is never stopped.
#
# Usage: ./restore-test.sh [--image <ref>] <archive.tar.gz | backup-dir> [container-name]
# Exit:  0 identical and usable   1 mismatch, an unextractable archive, or a failed check   2 could not test
set -euo pipefail

IMAGE=""
POSITIONAL=()
while [ $# -gt 0 ]; do
  case "$1" in
    --image) IMAGE="${2:?--image needs an image reference}"; shift 2 ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done
set -- "${POSITIONAL[@]+"${POSITIONAL[@]}"}"

TARGET="${1:?usage: restore-test.sh [--image <ref>] <archive.tar.gz | backup-dir> [container-name]}"
CONTAINER="${2:-qertum}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! docker info >/dev/null 2>&1; then
  echo "error: the Docker daemon is not reachable" >&2
  exit 2
fi

ARCHIVE=""
if [ -d "${TARGET}" ]; then
  # Newest archive that has a manifest; a newer one without it (taken before manifests existed) is skipped.
  # "Newest" is by name: it carries the UTC time of the backup, whereas a copy off-box or a touch changes
  # the modified time. The glob expands in ascending order, so the last match wins.
  for candidate in "${TARGET}"/qertum-backup-*.tar.gz; do
    if [ -f "${candidate}" ] && [ -f "${candidate%.tar.gz}.manifest" ]; then
      ARCHIVE="${candidate}"
    fi
  done
  if [ -z "${ARCHIVE}" ]; then
    echo "error: no archive with a manifest in ${TARGET}" >&2
    exit 2
  fi
elif [ -f "${TARGET}" ]; then
  ARCHIVE="${TARGET}"
else
  echo "error: not found: ${TARGET}" >&2
  exit 2
fi

case "${ARCHIVE}" in
  *.tar.gz) ;;
  *) echo "error: ${ARCHIVE} is not a .tar.gz archive" >&2; exit 2 ;;
esac

MANIFEST="${ARCHIVE%.tar.gz}.manifest"
if [ ! -f "${MANIFEST}" ]; then
  echo "error: no manifest next to ${ARCHIVE} (expected ${MANIFEST}); a backup taken before manifests existed cannot be verified" >&2
  exit 2
fi

ARCHIVE_DIR="$(cd "$(dirname "${ARCHIVE}")" && pwd)"
ARCHIVE_FILE="$(basename "${ARCHIVE}")"
VOLUME="qertum-restore-test-$(date -u +%Y%m%dT%H%M%SZ)-$$"
ACTUAL="$(mktemp)"

cleanup() {
  # The scratch volume holds a copy of /data, CA private keys included: say so if it cannot be removed.
  if ! docker volume rm -f "${VOLUME}" >/dev/null 2>&1; then
    echo "warning: could not remove the scratch volume ${VOLUME}; it holds a copy of the backup, so remove it with: docker volume rm ${VOLUME}" >&2
  fi
  rm -f "${ACTUAL}"
}
trap cleanup EXIT

# Writes /data/recovery/last-restore.json on the operating container's volume, atomically. The helper script
# has no double quotes (\042) so the .ps1 twin can share it through Windows native-argument quoting.
# Usage: record <usable|verified>   or   record failed <manifest|usability> <failedCheck>
read -r -d '' RECORD_SCRIPT <<'EOS' || true
set -e
mkdir -p /data/recovery
chmod 755 /data/recovery
if [ -n "$STEP" ]; then
  printf '{\042schemaVersion\042:1,\042kind\042:\042%s\042,\042completedAtUtc\042:\042%s\042,\042archiveName\042:\042%s\042,\042step\042:\042%s\042,\042failedCheck\042:\042%s\042,\042reportedBy\042:\042%s\042}\n' "$KIND" "$COMPLETED" "$ARCHIVE" "$STEP" "$CHECK" "$BY" > /data/recovery/last-restore.json.tmp
else
  printf '{\042schemaVersion\042:1,\042kind\042:\042%s\042,\042completedAtUtc\042:\042%s\042,\042archiveName\042:\042%s\042,\042reportedBy\042:\042%s\042}\n' "$KIND" "$COMPLETED" "$ARCHIVE" "$BY" > /data/recovery/last-restore.json.tmp
fi
chmod 644 /data/recovery/last-restore.json.tmp
mv /data/recovery/last-restore.json.tmp /data/recovery/last-restore.json
EOS

record() {
  local kind="$1" step="${2:-}" check="${3:-}"
  if ! docker inspect "${CONTAINER}" >/dev/null 2>&1; then
    echo "warning: container '${CONTAINER}' not found, so nothing was recorded for the Qertum dashboard" >&2
    return 0
  fi
  docker run --rm --volumes-from "${CONTAINER}" \
    -e KIND="${kind}" -e STEP="${step}" -e CHECK="${check}" -e BY="restore-test.sh" \
    -e COMPLETED="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -e ARCHIVE="$(printf '%s' "${ARCHIVE_FILE}" | tr -c 'A-Za-z0-9._-' '_')" \
    alpine sh -c "${RECORD_SCRIPT}" \
    || echo "warning: the result could not be recorded for the Qertum dashboard" >&2
}

if ! docker volume create "${VOLUME}" >/dev/null; then
  echo "error: could not create the scratch volume" >&2
  exit 2
fi

echo "Extracting ${ARCHIVE_FILE} into scratch volume ${VOLUME}..."
EXTRACT_STATUS=0
docker run --rm -v "${VOLUME}":/data -v "${ARCHIVE_DIR}":/backup:ro \
  alpine tar xzf "/backup/${ARCHIVE_FILE}" -C / || EXTRACT_STATUS=$?
if [ "${EXTRACT_STATUS}" -ne 0 ]; then
  # 125, 126 and 127 are docker's own failures (it could not start the container); anything else is tar's.
  case "${EXTRACT_STATUS}" in
    125|126|127)
      echo "error: docker could not run the extraction (exit ${EXTRACT_STATUS})" >&2
      exit 2
      ;;
  esac
  echo "FAILED: the archive could not be extracted; it is damaged or incomplete" >&2
  record failed manifest archive
  exit 1
fi

if ! docker run --rm -v "${VOLUME}":/data:ro -v "${SCRIPT_DIR}/manifest.sh":/manifest.sh:ro \
       alpine sh /manifest.sh > "${ACTUAL}"; then
  echo "error: could not read the extracted files" >&2
  exit 2
fi

# Compare path by path. Fields are separated by two spaces; the path is the rest of the line.
DIFFS="$(awk -v FS='  ' '
  function pathOf() { return substr($0, length($1 FS $2 FS $3 FS $4 FS) + 1) }
  NR == FNR { p = pathOf(); eh[p] = $1; em[p] = $2; eo[p] = $3; want[p] = 1; next }
  {
    p = pathOf(); got[p] = 1
    if (!(p in want)) { print "extra    " p; next }
    if ($1 != eh[p]) print "content  " p
    if ($2 != em[p]) print "mode     " p " (" em[p] " -> " $2 ")"
    if ($3 != eo[p]) print "owner    " p " (" eo[p] " -> " $3 ")"
  }
  END { for (p in want) if (!(p in got)) print "missing  " p }
' "${MANIFEST}" "${ACTUAL}" | LC_ALL=C sort)"

if [ -n "${DIFFS}" ]; then
  COUNT="$(printf '%s\n' "${DIFFS}" | wc -l | tr -d ' ')"
  echo "FAILED: ${ARCHIVE_FILE} does not match its manifest (${COUNT} differences):" >&2
  printf '%s\n' "${DIFFS}" | sed 's/^/  /' >&2
  record failed manifest manifest
  exit 1
fi

FILES="$(wc -l < "${MANIFEST}" | tr -d ' ')"
echo "Verified: ${ARCHIVE_FILE} matches its manifest (${FILES} files)."

# Step 2: boot the restored copy offline. The image defaults to the operating container's own.
if [ -z "${IMAGE}" ] && docker inspect "${CONTAINER}" >/dev/null 2>&1; then
  IMAGE="$(docker inspect -f '{{.Config.Image}}' "${CONTAINER}")"
fi
if [ -z "${IMAGE}" ]; then
  echo "warning: no image to open the restored copy with (container '${CONTAINER}' not found and no --image); only the manifest was checked" >&2
  record verified
  exit 0
fi

echo "Opening the restored copy offline with ${IMAGE} (no network, no services)..."
CHECK_STATUS=0
CHECK_OUT="$(docker run --rm --network none --user 1654:1654 -v "${VOLUME}":/data \
  --entrypoint dotnet "${IMAGE}" /app/restorecheck/Qertum.RestoreCheck.dll /data)" || CHECK_STATUS=$?
printf '%s\n' "${CHECK_OUT}"

case "${CHECK_STATUS}" in
  0)
    echo "Usable: the restored copy was opened offline and the checks above passed."
    # A check with nothing to test (no encrypted secret, no online issuer, a CA never onboarded) is not a pass.
    NOT_EXERCISED="$(printf '%s\n' "${CHECK_OUT}" | awk '$1 == "check" && $3 == "not-exercised" { printf "%s ", $2 }')"
    if [ -n "${NOT_EXERCISED}" ]; then
      echo "note: not exercised: ${NOT_EXERCISED}- 'usable' says nothing about those." >&2
    fi
    record usable
    ;;
  1)
    FAILED_CHECK="$(printf '%s\n' "${CHECK_OUT}" | awk '$1 == "check" && $3 == "fail" && !seen { print $2; seen = 1 }' | tr -d '\n' | tr -c 'A-Za-z0-9._:-' '_' | cut -c1-32)"
    echo "FAILED: the restored copy does not work (check: ${FAILED_CHECK:-unknown})" >&2
    record failed usability "${FAILED_CHECK:-usability}"
    exit 1
    ;;
  *)
    echo "error: the restored copy could not be tested with ${IMAGE} (exit ${CHECK_STATUS}); an image older than the check has no Qertum.RestoreCheck" >&2
    exit 2
    ;;
esac
