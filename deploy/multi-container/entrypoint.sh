#!/usr/bin/env bash
#
# Entrypoint for the multi-container image: one container runs the one service named by SERVICE.
#
#   1. Make /data writable for the unprivileged `app` user and drop root (same as the
#      single-container entrypoint).
#   2. Derive the cross-service configuration the Aspire AppHost normally injects. Every container
#      gets the same variables; a service ignores the ones it does not read.
#   3. exec the service.
#
set -euo pipefail

VALID_SERVICES="identityservice apiservice webfrontend acmeservice estservice queueconsumer"
SERVICE="${SERVICE:-}"

case " ${VALID_SERVICES} " in
  *" ${SERVICE} "*) ;;
  *)
    echo "error: unknown or missing SERVICE '${SERVICE}'. Valid values: ${VALID_SERVICES}" >&2
    exit 64
    ;;
esac

DATA_DIR="/data"
IDENTITY_DATA_DIR="${DATA_DIR}/identity"

if [ "$(id -u)" = "0" ]; then
  mkdir -p "${DATA_DIR}" "${IDENTITY_DATA_DIR}"
  app_uid="$(id -u app)"
  if [ "$(stat -c %u "${DATA_DIR}")" != "${app_uid}" ] || find "${DATA_DIR}" -not -user app -print -quit | grep -q .; then
    echo "Making ${DATA_DIR} writable for the unprivileged app user (one-time after an upgrade)..."
    chown -R app:app "${DATA_DIR}" || echo "WARNING: could not chown ${DATA_DIR}; the service may be unable to write to it." >&2
  fi
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
# Public host, ports and scheme. Browsers and ACME/EST clients reach each service at
# <scheme>://<QERTUM_HOST>:<port>. EST is always https: its mTLS needs Kestrel's own TLS.
# ---------------------------------------------------------------------------
QERTUM_HOST="${QERTUM_HOST:-localhost}"
QERTUM_SCHEME="${QERTUM_SCHEME:-http}"
# ACME may not sit behind a TLS-terminating proxy, so its scheme is separate from QERTUM_SCHEME (which is
# for a proxy in front of web, identity and API): https only when the acme container terminates TLS itself.
ACME_SCHEME="${ACME_SCHEME:-http}"
WEB_PORT="${WEB_PORT:-8080}"
IDENTITY_PORT="${IDENTITY_PORT:-8081}"
API_PORT="${API_PORT:-8082}"
ACME_PORT="${ACME_PORT:-8083}"
EST_PORT="${EST_PORT:-8084}"

# Browsers and API clients reach web, identity and API over QERTUM_SCHEME. Plain http sends sign-in, access tokens and
# the administrator password unencrypted; say so on every start of a service that carries them.
if [ "${QERTUM_SCHEME}" = "http" ]; then
  case "${SERVICE:-}" in
    webfrontend|identityservice|apiservice)
      echo "WARNING: QERTUM_SCHEME is http: sign-in, access tokens and the admin password cross the network" >&2
      echo "         unencrypted. Use it only on a trusted network; otherwise put a TLS-terminating proxy in front" >&2
      echo "         and set QERTUM_SCHEME=https." >&2
      ;;
  esac
fi

# Every spelling of "this container" (localhost in any case, 127.x.x.x, ::1, 0.0.0.0) is a name that
# only works from outside: inside a container it is the container itself.
host_lc="$(printf '%s' "${QERTUM_HOST}" | tr '[:upper:]' '[:lower:]')"
case "${host_lc}" in
  localhost|127.*|::1|\[::1\]|0.0.0.0)
    case "${SERVICE}" in
      apiservice|webfrontend)
        # Both fetch the identity service's metadata from the advertised authority, which could only
        # ever answer "connection refused" from inside a container.
        echo "error: QERTUM_HOST must not be 'localhost' (or 127.x.x.x, ::1, 0.0.0.0) in the multi-container layout: ${SERVICE} could not reach the identity service. Set it to a host name or IP reachable from the containers and from clients (on Docker Desktop, host.docker.internal)." >&2
        exit 64
        ;;
    esac
    echo "WARNING: QERTUM_HOST is '${QERTUM_HOST}'. Set it to the host name or IP clients use," >&2
    echo "         or browser login and ACME/EST will fail." >&2
    ;;
esac
if [ "${SERVICE:-}" = "webfrontend" ]; then
  echo "NOTE: open Qertum at ${QERTUM_SCHEME}://${QERTUM_HOST}:${WEB_PORT} exactly. Sign-in accepts only this" >&2
  echo "      address; localhost, 127.0.0.1 or another name or IP fails with ID2043 (redirect_uri not valid)." >&2
fi

# Seeds the qertum-api client in the identity service; stable across restarts.
SECRET_FILE="${DATA_DIR}/.api-introspection-secret"
if [ -z "${QERTUM_API_INTROSPECTION_SECRET:-}" ]; then
  if [ -f "${SECRET_FILE}" ]; then
    QERTUM_API_INTROSPECTION_SECRET="$(cat "${SECRET_FILE}")"
  elif [ "${SERVICE}" = "identityservice" ]; then
    # Only the identity service creates it, so containers starting together cannot race to write two.
    QERTUM_API_INTROSPECTION_SECRET="$(head -c 32 /dev/urandom | base64 | tr -d '/+=' )"
    printf '%s' "${QERTUM_API_INTROSPECTION_SECRET}" > "${SECRET_FILE}"
    chmod 600 "${SECRET_FILE}"
    echo "Generated a new API introspection secret at ${SECRET_FILE}."
  fi
fi

export ASPNETCORE_ENVIRONMENT="${ASPNETCORE_ENVIRONMENT:-Production}"
export ConnectionStrings__CertificateRequests="Data Source=${DATA_DIR}/certificate-requests.db"
export ConnectionStrings__cache="${REDIS_ADDRESS:-cache:6379}"
export IdentityService__DataPath="${IDENTITY_DATA_DIR}"
export ConnectionStrings__Identity="Data Source=${IDENTITY_DATA_DIR}/identity.db"
export IdentityService__Authority="${QERTUM_SCHEME}://${QERTUM_HOST}:${IDENTITY_PORT}"
export IdentityService__ApiClientSecret="${QERTUM_API_INTROSPECTION_SECRET:-}"
export IdentityService__SeedAdminPassword="${IdentityService__SeedAdminPassword:-}"
export Identity__Authority="${QERTUM_SCHEME}://${QERTUM_HOST}:${IDENTITY_PORT}"
export Identity__RequireHttpsMetadata="${Identity__RequireHttpsMetadata:-false}"
# Web -> API is server-side only, over the compose network.
export ApiService__BaseUrl="${ApiService__BaseUrl:-http://apiservice:8082}"
export Acme__BaseUrl="${ACME_SCHEME}://${QERTUM_HOST}:${ACME_PORT}"
# Display only: the URL the Web UI prints in its automation snippets for pipelines.
export Automation__ApiUrl="${QERTUM_SCHEME}://${QERTUM_HOST}:${API_PORT}"
export Enrollment__AcmeDirectoryUrl="${ACME_SCHEME}://${QERTUM_HOST}:${ACME_PORT}/acme/directory"
export Enrollment__EstBaseUrl="https://${QERTUM_HOST}:${EST_PORT}/.well-known/est"
export "Services__webfrontend__${QERTUM_SCHEME}__0=${QERTUM_SCHEME}://${QERTUM_HOST}:${WEB_PORT}"
export IdentityService__EnableServiceDiscoveryRedirectUris="${IdentityService__EnableServiceDiscoveryRedirectUris:-true}"
export IdentityService__DisableTransportSecurity="${IdentityService__DisableTransportSecurity:-true}"
export OpenIdConnect__RequireHttpsMetadata="${OpenIdConnect__RequireHttpsMetadata:-false}"

# ---------------------------------------------------------------------------
# Per-service listening address. ASPNETCORE_URLS may be overridden for a service that terminates
# TLS itself (Kestrel__Endpoints__* is the alternative); the port must stay the one below, because
# healthcheck.sh probes it.
# ---------------------------------------------------------------------------
case "${SERVICE}" in
  webfrontend)     dll="Qertum.Web.dll";             port=8080 ;;
  identityservice) dll="Qertum.IdentityService.dll"; port=8081 ;;
  apiservice)      dll="Qertum.ApiService.dll";      port=8082 ;;
  acmeservice)     dll="Qertum.AcmeService.dll";     port=8083 ;;
  estservice)      dll="Qertum.EstService.dll";      port=8084 ;;
  queueconsumer)   dll="Qertum.QueueConsumer.dll";   port="" ;;
esac

if [ -n "${port}" ]; then
  scheme_for_listen="http"
  [ "${SERVICE}" = "estservice" ] && scheme_for_listen="https"
  export ASPNETCORE_URLS="${ASPNETCORE_URLS:-${scheme_for_listen}://0.0.0.0:${port}}"
fi

if [ "${SERVICE}" = "estservice" ]; then
  if [ ! -r /run/est/tls.crt ] || [ ! -r /run/est/tls.key ]; then
    echo "error: estservice requires a server certificate: mount a PEM certificate chain at /run/est/tls.crt and its key at /run/est/tls.key (readable by UID 1654)." >&2
    exit 64
  fi
  export ASPNETCORE_URLS="https://0.0.0.0:8084"
  export Kestrel__Certificates__Default__Path="/run/est/tls.crt"
  export Kestrel__Certificates__Default__KeyPath="/run/est/tls.key"
fi

# Behind the TLS proxy that QERTUM_SCHEME=https stands for, web, identity and API see the proxy's plain-http
# hop and must take the client's scheme and address from X-Forwarded-Proto/-For: without it the identity
# service refuses every request ("This server only accepts HTTPS requests") and builds http URLs. This trusts
# the headers from whoever connects, which is the proxy alone only while their ports are not published to
# anyone else (README). ACME and EST never sit behind a proxy, so they never trust the headers.
case "${SERVICE}" in
  webfrontend|identityservice|apiservice)
    if [ "${QERTUM_SCHEME}" = "https" ]; then
      export ASPNETCORE_FORWARDEDHEADERS_ENABLED="${ASPNETCORE_FORWARDEDHEADERS_ENABLED:-true}"
    fi ;;
  *) unset ASPNETCORE_FORWARDEDHEADERS_ENABLED ;;
esac

echo "Qertum ${SERVICE} starting (data ${DATA_DIR}, host ${QERTUM_HOST})"
cd "/app/${SERVICE}"
exec dotnet "${dll}"
