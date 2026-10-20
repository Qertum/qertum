#!/usr/bin/env bash
#
# Restore the /data volume of the multi-container deployment from an archive made by backup.sh.
#
# Stops every Qertum container except the one that supplies the volume (qertum-apiservice), then runs
# the single-container restore.sh against that one. That script asks for confirmation first; declining
# (or any failure) restarts the others again. Redis keeps running. # qertum-cache keeps running
#
# Usage: ./restore.sh <archive.tar.gz>
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VOLUME_CONTAINER="qertum-apiservice"
OTHERS="qertum-identityservice qertum-webfrontend qertum-acmeservice qertum-estservice qertum-queueconsumer"

stopped=""
restart_others() {
  for c in ${stopped}; do
    echo "Restarting ${c}..."
    docker start "${c}" >/dev/null || echo "warning: could not restart ${c}" >&2
  done
}
trap restart_others EXIT

for c in ${OTHERS}; do
  if [ "$(docker inspect -f '{{.State.Running}}' "${c}" 2>/dev/null || echo false)" = "true" ]; then
    echo "Stopping ${c}..."
    docker stop "${c}" >/dev/null
    stopped="${stopped} ${c}"
  fi
done

"${SCRIPT_DIR}/../single-container/restore.sh" "${1:?usage: restore.sh <archive.tar.gz>}" "${VOLUME_CONTAINER}"
