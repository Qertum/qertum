#!/usr/bin/env bash
#
# Entrypoint for the single-container Qertum stack.
#
# Responsibilities:
#   1. Derive the cross-service configuration the Aspire AppHost normally injects,
#      wiring every service over localhost / the host's public URLs.
#   2. Keep all mutable state on the /data volume so redeploys never lose the CA,
#      the database, the Data Protection keyring or the identity provider's users.
#   3. Launch Redis and the five services under runit (runsvdir), and shut them down cleanly on
#      SIGTERM.
#
set -euo pipefail

DATA_DIR="/data"
IDENTITY_DATA_DIR="${DATA_DIR}/identity"
IDENTITY_APP_DIR="/app/identityservice"

# ---------------------------------------------------------------------------
# Privilege drop. The container starts as root only so it can make /data writable for
# the unprivileged `app` user (UID 1654, from the base image): a volume written by an
# older, root-running image is re-owned once. Then this script re-executes itself as
# `app`, so Redis, runit and every .NET process run without root. Started with
# `--user` (already non-root) it skips all of this and expects a writable /data.
# ---------------------------------------------------------------------------
adopt_identity_item() {
  local name="$1"
  local app_path="${IDENTITY_APP_DIR}/${name}"
  local vol_path="${IDENTITY_DATA_DIR}/${name}"
  if [ -L "${app_path}" ]; then
    rm -f "${app_path}"
  elif [ -e "${app_path}" ]; then
    if [ ! -e "${vol_path}" ]; then
      mv "${app_path}" "${vol_path}"
      echo "Moved ${name} onto the volume."
    else
      echo "WARNING: ${app_path} and ${vol_path} both exist; keeping the volume's copy." >&2
    fi
  fi
}

if [ "$(id -u)" = "0" ]; then
  mkdir -p "${DATA_DIR}" "${IDENTITY_DATA_DIR}"

  # Images before IdentityService__DataPath (below) kept some state in the image's
  # writable layer, partly symlinked onto /data: move any real file still there onto
  # the volume (unless the volume already has it), and drop the old symlinks. Needs
  # root because the app directory is owned by root. State lost to an earlier
  # container re-creation cannot be recovered here.
  for item in clients.json users.json roles.json keys secret-storage secret-storage.json \
              audit-logs api-client-secret.txt; do
    adopt_identity_item "${item}"
  done

  app_uid="$(id -u app)"
  if [ "$(stat -c %u "${DATA_DIR}")" != "${app_uid}" ] || find "${DATA_DIR}" -not -user app -print -quit | grep -q .; then
    echo "Making ${DATA_DIR} writable for the unprivileged app user (one-time after an upgrade)..."
    chown -R app:app "${DATA_DIR}" || echo "WARNING: could not chown ${DATA_DIR}; the services may be unable to write to it." >&2
  fi

  # Every service writes its log to /dev/stdout and /dev/stderr. The container's own
  # stdout/stderr belong to root, so without this the unprivileged user gets EACCES and
  # no service starts. Hand them to `app`; best effort, a runtime that already allows
  # writing needs nothing.
  # (Address this shell's descriptors through $$: a redirect on the chown command itself would
  # replace the very stderr it is meant to hand over.)
  chown app:app /proc/$$/fd/1 /proc/$$/fd/2 2>/dev/null || chmod o+w /proc/$$/fd/1 /proc/$$/fd/2 2>/dev/null || true

  export HOME=/home/app
  # `--init-groups` would reset the supplementary groups to those of `app` and silently drop the one
  # `group_add` / `--group-add` grants for the TPM device, so LocalTpm could never open /dev/tpmrm0.
  # Keep the groups the runtime added, minus root's group 0.
  app_groups="$(id -G app | tr ' ' ',')"
  extra_groups="$(id -G | tr ' ' '\n' | grep -vx 0 | paste -sd, - || true)"
  exec setpriv --reuid=app --regid=app --groups "${app_groups}${extra_groups:+,${extra_groups}}" "$0" "$@"
fi

mkdir -p "${DATA_DIR}" "${IDENTITY_DATA_DIR}"

# ---------------------------------------------------------------------------
# Public host + ports. With direct port exposure the browser and ACME clients
# reach the services at http://<QERTUM_HOST>:<port>, so the OIDC authority and
# ACME base URL must be the host-reachable address, not localhost.
# ---------------------------------------------------------------------------
QERTUM_HOST="${QERTUM_HOST:-localhost}"
WEB_PORT="${WEB_PORT:-8080}"
IDENTITY_PORT="${IDENTITY_PORT:-8081}"
API_PORT="${API_PORT:-8082}"
ACME_PORT="${ACME_PORT:-8083}"

if [ "${QERTUM_HOST}" = "localhost" ]; then
  echo "WARNING: QERTUM_HOST is 'localhost'. Set it to the Unraid host IP/hostname" >&2
  echo "         (e.g. -e QERTUM_HOST=192.168.1.50) or browser login and ACME will fail." >&2
fi

# ---------------------------------------------------------------------------
# IdentityService's client-seeding secret (used only to seed/verify OpenIddict
# client entries, e.g. qca — ApiService no longer participates in this,
# it validates bearer tokens as plain OIDC JWTs, not via introspection).
# Provide it via QERTUM_API_INTROSPECTION_SECRET, otherwise generate once and
# persist on the volume so it stays stable across restarts/redeploys.
# ---------------------------------------------------------------------------
SECRET_FILE="${DATA_DIR}/.api-introspection-secret"
if [ -z "${QERTUM_API_INTROSPECTION_SECRET:-}" ]; then
  if [ -f "${SECRET_FILE}" ]; then
    QERTUM_API_INTROSPECTION_SECRET="$(cat "${SECRET_FILE}")"
  else
    QERTUM_API_INTROSPECTION_SECRET="$(head -c 32 /dev/urandom | base64 | tr -d '/+=' )"
    printf '%s' "${QERTUM_API_INTROSPECTION_SECRET}" > "${SECRET_FILE}"
    chmod 600 "${SECRET_FILE}"
    echo "Generated a new API introspection secret at ${SECRET_FILE}."
  fi
fi

# ---------------------------------------------------------------------------
# Cross-service configuration (exported -> inherited by every service runit starts).
# Setting variables that a given service ignores is harmless.
# ---------------------------------------------------------------------------
export ASPNETCORE_ENVIRONMENT="${ASPNETCORE_ENVIRONMENT:-Production}"

# Shared SQLite DB for api/acme/consumer. The CA files (CaData/), Data Protection
# keyring (DataProtection-Keys/) and audit logs (audit-logs/) are derived from this
# directory, so they all land on the volume automatically.
export ConnectionStrings__CertificateRequests="Data Source=${DATA_DIR}/certificate-requests.db"

# Shared Redis (run by runit in this container, loopback only). Without it each process
# keeps its own in-memory cache, so a CRL published or evicted by queueconsumer would
# never reach apiservice, which serves /crl.
export ConnectionStrings__cache="127.0.0.1:6379"


# Everything IdentityService owns: users/clients/roles, keys/ and the key that
# protects them (secret-storage/), its audit log, and its OpenIddict store.
export IdentityService__DataPath="${IDENTITY_DATA_DIR}"
export ConnectionStrings__Identity="Data Source=${IDENTITY_DATA_DIR}/identity.db"

# OIDC authority for Web's login flow — must be browser-reachable.
export IdentityService__Authority="http://${QERTUM_HOST}:${IDENTITY_PORT}"

# Fed into ClientSeedHostedService so it seeds a stable qertum-api client secret
# in clients.json across restarts/redeploys (see the SECRET_FILE block above).
export IdentityService__ApiClientSecret="${QERTUM_API_INTROSPECTION_SECRET}"

# Optional operator-chosen password for the first-run admin account. Unset means the
# well-known default, which the first login is forced to change.
export IdentityService__SeedAdminPassword="${IdentityService__SeedAdminPassword:-}"

# ApiService validates bearer tokens as standard OIDC JWTs against the issuer above —
# it needs no client secret of its own. Identity:Authority must be browser/worker-reachable
# (same host:port as IdentityService__Authority) and, since this deployment is plain HTTP
# by design, RequireHttpsMetadata must be turned off to match.
export Identity__Authority="http://${QERTUM_HOST}:${IDENTITY_PORT}"
export Identity__RequireHttpsMetadata="${Identity__RequireHttpsMetadata:-false}"

# Web -> API is server-side only (Blazor Server circuit), so it can stay on localhost.
export ApiService__BaseUrl="http://localhost:${API_PORT}"

# ACME directory/resource links advertised to certbot/cert-manager.
export Acme__BaseUrl="http://${QERTUM_HOST}:${ACME_PORT}"

# Display only: the URL the Web UI prints in its automation snippets for pipelines.
export Automation__ApiUrl="http://${QERTUM_HOST}:${API_PORT}"

# The enrollment wizard offers ACME, with its client setup examples, only when it
# knows the directory URL. EST is not in this image, so no EST URL.
export Enrollment__AcmeDirectoryUrl="http://${QERTUM_HOST}:${ACME_PORT}/acme/directory"

# Drives ClientSeedHostedService to register the web app's redirect URIs
# (<base>/signin-oidc, <base>/signout-callback-oidc) without editing clients.json.
export Services__webfrontend__http__0="http://${QERTUM_HOST}:${WEB_PORT}"

# ClientSeedHostedService only reads Services__webfrontend__* when this is on
# (default: Development only). This deployment runs Production but injects the
# variable deliberately, so opt in explicitly.
export IdentityService__EnableServiceDiscoveryRedirectUris="${IdentityService__EnableServiceDiscoveryRedirectUris:-true}"

# Allow plain-HTTP transport for the OIDC server and client metadata (LAN / TLS
# terminated elsewhere). Opt-in flags added to the app; default behavior unchanged.
export IdentityService__DisableTransportSecurity="${IdentityService__DisableTransportSecurity:-true}"
export OpenIdConnect__RequireHttpsMetadata="${OpenIdConnect__RequireHttpsMetadata:-false}"

echo "Qertum single-container starting:"
echo "  Web      http://${QERTUM_HOST}:${WEB_PORT}"
echo "  Identity http://${QERTUM_HOST}:${IDENTITY_PORT}"
echo "  API      http://${QERTUM_HOST}:${API_PORT}"
echo "  ACME     http://${QERTUM_HOST}:${ACME_PORT}/acme/directory"
echo "  Data     ${DATA_DIR}"

# ---------------------------------------------------------------------------
# Run the services. runit's service directory must be writable (runsv keeps its control files
# in it) and /etc is not, so the read-only templates from the image are copied to /tmp first.
# runsvdir starts one runsv per service; runsv restarts a service that exits, after a second.
# The container's PID 1 is tini, which reaps orphans and forwards signals to this script: on
# SIGTERM/SIGINT the trap asks every service to stop (TERM, then exit) and waits for them, so
# `docker stop` is graceful instead of a SIGKILL after the grace period.
# ---------------------------------------------------------------------------
SVC_DIR="${QERTUM_SVC_DIR:-/tmp/qertum-svc}"
rm -rf "${SVC_DIR}"
mkdir -p "${SVC_DIR}"
cp -R /etc/qertum/service/. "${SVC_DIR}/"

runsvdir -P "${SVC_DIR}" &
RUNSVDIR_PID=$!

shutdown() {
  echo "Stopping services..."
  sv -w 60 exit "${SVC_DIR}"/* || true
  kill -HUP "${RUNSVDIR_PID}" 2>/dev/null || true
}
trap shutdown TERM INT

# `wait` returns as soon as the trap has run; wait again for runsvdir to finish going away.
wait "${RUNSVDIR_PID}" || true
wait "${RUNSVDIR_PID}" 2>/dev/null || true
