#!/usr/bin/env bash
#
# Docker HEALTHCHECK for the multi-container image. The services' own /health endpoints are
# Development-only and the base image has no curl, so this opens a TCP connection to the
# service's fixed listen port (see entrypoint.sh). The queue consumer has no endpoint: it is
# checked by looking for its process.
set -euo pipefail

case "${SERVICE:-}" in
  webfrontend)     port=8080 ;;
  identityservice) port=8081 ;;
  apiservice)      port=8082 ;;
  acmeservice)     port=8083 ;;
  estservice)      port=8084 ;;
  queueconsumer)
    if grep -l "Qertum.QueueConsumer.dll" /proc/[0-9]*/cmdline >/dev/null 2>&1; then
      exit 0
    fi
    echo "healthcheck: queueconsumer process not found" >&2
    exit 1
    ;;
  *) echo "healthcheck: unknown SERVICE '${SERVICE:-}'" >&2; exit 1 ;;
esac

if exec 3<>"/dev/tcp/127.0.0.1/${port}"; then
  exec 3>&-
  exit 0
fi
echo "healthcheck: nothing is listening on ${port}" >&2
exit 1
