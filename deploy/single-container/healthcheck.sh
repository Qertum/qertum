#!/usr/bin/env bash
#
# Docker HEALTHCHECK for the single-container Qertum stack.
#
# The five services' own /health and /alive endpoints are only mapped in
# Development (see Qertum.ServiceDefaults/Extensions.cs), and this image runs
# ASPNETCORE_ENVIRONMENT=Production, so we can't probe them over HTTP. Instead
# ask runit (which is already watching all six processes) for status.
#
# Healthy means every service is `run` and has been up for at least MIN_UPTIME seconds.
# runit restarts a crashing service every second, so "running right now" alone would pass in
# the instant between two crashes; a service that keeps dying never reaches the minimum uptime.
set -euo pipefail

SVC_DIR="${QERTUM_SVC_DIR:-/tmp/qertum-svc}"
MIN_UPTIME=5

status="$(sv status "${SVC_DIR}"/* 2>&1)" || true
echo "${status}"

# Line shape: `run: /tmp/qertum-svc/redis: (pid 12) 34s`, or `down: ...` / `run: ...: (pid 12) 0s` after a restart.
if [ -z "${status}" ] || echo "${status}" | awk -v min="${MIN_UPTIME}" '
      { up = $5; sub(/s;?$/, "", up) }
      !($1 == "run:" && up + 0 >= min) { bad = 1 }
      END { exit bad ? 0 : 1 }'; then
  echo "healthcheck: at least one service is not running (or has been up less than ${MIN_UPTIME}s)" >&2
  exit 1
fi

exit 0
