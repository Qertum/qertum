#!/bin/sh
#
# Entrypoint for the standalone identity image.
#
# The container starts as root only so it can make the data volume writable for the
# unprivileged `app` user (UID 1654, from the base image): a volume written by an older,
# root-running image is re-owned once. Then the IdP itself runs as `app`. Started with
# `--user` (already non-root) it skips the ownership step and expects a writable volume.
set -eu

DATA_DIR="${IdentityService__DataPath:-/data}"

if [ "$(id -u)" = "0" ]; then
  mkdir -p "${DATA_DIR}"
  if [ "$(stat -c %u "${DATA_DIR}")" != "$(id -u app)" ] || find "${DATA_DIR}" -not -user app -print -quit | grep -q .; then
    echo "Making ${DATA_DIR} writable for the unprivileged app user (one-time after an upgrade)..."
    chown -R app:app "${DATA_DIR}" || echo "WARNING: could not chown ${DATA_DIR}; the identity service may be unable to write to it." >&2
  fi
  export HOME=/home/app
  # `--init-groups` would reset the supplementary groups to those of `app` and silently drop the one
  # `group_add` / `--group-add` grants for the TPM device, so LocalTpm could never open /dev/tpmrm0.
  # Keep the groups the runtime added, minus root's group 0.
  app_groups="$(id -G app | tr ' ' ',')"
  extra_groups="$(id -G | tr ' ' '\n' | grep -vx 0 | paste -sd, - || true)"
  exec setpriv --reuid=app --regid=app --groups "${app_groups}${extra_groups:+,${extra_groups}}" dotnet Qertum.IdentityService.dll "$@"
fi

exec dotnet Qertum.IdentityService.dll "$@"
