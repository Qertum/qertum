#!/usr/bin/env bash
#
# Back up the /data volume of the multi-container deployment.
#
# SQLite and the CA files are not safe to archive while services write, so every Qertum container
# is stopped for the duration. This wrapper stops all of them except the one that supplies the volume
# (qertum-apiservice), then runs the single-container backup.sh against that one, which stops it,
# archives, records the status and restarts it. Redis keeps running: it holds only regenerable cache
# entries. # qertum-cache keeps running
# The other containers are restarted on any exit, including a failure.
#
# Usage: ./backup.sh [output-dir]
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

"${SCRIPT_DIR}/../single-container/backup.sh" "${1:-.}" "${VOLUME_CONTAINER}"
