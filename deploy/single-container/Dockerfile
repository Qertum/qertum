# syntax=docker/dockerfile:1

# Single-container image bundling the entire Qertum stack (the five services the
# Aspire AppHost normally orchestrates) into one container, supervised by runit.
# Intended for homelab / Unraid deployments. See deploy/single-container/README.md.

# ---------------------------------------------------------------------------
# Build stage: restore + publish each runtime service into its own /app folder.
# ---------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:212fe4cb74627d5adf9817a4088906ae3edff1bd853bb27565d4b46731efe61e AS build
WORKDIR /src

# Copy the whole repo. (The projects share many references; a partial copy buys
# little here and is brittle as the solution grows.)
COPY . .

# Publish the runtime services, plus the offline restore check (an operator tool run by restore-test, not a service). AppHost, Tests and the CLI are intentionally
# excluded — they are not part of the running stack.
RUN dotnet publish Qertum.IdentityService/Qertum.IdentityService.csproj -c Release -o /app/identityservice && \
    dotnet publish Qertum.ApiService/Qertum.ApiService.csproj         -c Release -o /app/apiservice && \
    dotnet publish Qertum.AcmeService/Qertum.AcmeService.csproj       -c Release -o /app/acmeservice && \
    dotnet publish Qertum.Web/Qertum.Web.csproj                       -c Release -o /app/webfrontend && \
    dotnet publish Qertum.QueueConsumer/Qertum.QueueConsumer.csproj   -c Release -o /app/queueconsumer && \
    dotnet publish Qertum.RestoreCheck/Qertum.RestoreCheck.csproj     -c Release -o /app/restorecheck

# ---------------------------------------------------------------------------
# Valkey stage: only the server binary is taken from the official image, pinned by digest, so
# the shared cache runs the same Valkey version as the AppHost and the tests. Valkey (BSD-3-Clause,
# Redis-compatible) replaced Redis, whose version 8 is offered only under RSALv2, SSPLv1 or AGPLv3.
# No third-party apt repository is added to the runtime image. See "Bumping the base image" in the README.
# ---------------------------------------------------------------------------
FROM valkey/valkey:9.1@sha256:3add1a336a920ea54770a001ab6feb3da5fceea96a40373a3a2cd469b815f0b7 AS valkey

# ---------------------------------------------------------------------------
# Runtime stage: ASP.NET runtime + runit running Valkey and the five processes.
# ---------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/aspnet:10.0-resolute@sha256:c159e6c30ed39d4728d3d9f07f26dca10945896f7a072949cb9786ebcfea609d AS runtime

# runit supervises Valkey and the five .NET processes (it pulls in no Python, unlike the
# supervisord it replaced); tini is PID 1 and reaps orphans; tpm2-tools is for the LocalTpm
# secret-storage provider.
# The resolute base ships /usr/bin/pebble (a Go service manager) that nothing here runs; it only adds
# Go stdlib findings, so remove it.
# apt-get upgrade applies Ubuntu's security updates published since Microsoft last rebuilt the digest-pinned base
# (1.0.0-rc6: apt 3.2.0 had a fixable HIGH, CVE-2026-109518, that the publish-image Trivy gate refuses).
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends runit tini tpm2-tools \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/bin/pebble

# The shared cache's server (from the digest-pinned valkey stage above).
COPY --from=valkey /usr/local/bin/valkey-server /usr/local/bin/valkey-server

COPY --from=build /app /app
COPY LICENSE THIRD-PARTY-NOTICES.txt /usr/share/doc/qertum/
COPY deploy/single-container/service /etc/qertum/service
COPY deploy/single-container/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY deploy/single-container/healthcheck.sh /usr/local/bin/healthcheck.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/healthcheck.sh /etc/qertum/service/*/run

# Persistent state lives here (shared SQLite DB, Data Protection keyring, CA files,
# audit logs, and the identity service's db/keys/json). Mount a volume at /data.
RUN mkdir -p /data
VOLUME ["/data"]

# Internal HTTP ports (one per HTTP-facing service). queueconsumer has no endpoint.
#   8080 web | 8081 identity | 8082 api | 8083 acme
EXPOSE 8080 8081 8082 8083

# OCI image metadata. VERSION is passed by the publisher (`--build-arg VERSION=<tag>`).
ARG VERSION=dev
LABEL org.opencontainers.image.title="Qertum" \
      org.opencontainers.image.description="Qertum, a self-hosted certificate authority with post-quantum support (ML-DSA, SLH-DSA, ML-KEM and composite certificates). All-in-one image: web UI, identity service, REST API and ACME server in one container, data in one volume. For EST, or one container per service, use qertum-services. Documentation: https://github.com/Qertum/qertum/wiki" \
      org.opencontainers.image.source="https://github.com/Qertum/qertum" \
      org.opencontainers.image.url="https://github.com/Qertum/qertum/wiki" \
      org.opencontainers.image.documentation="https://github.com/Qertum/qertum/wiki" \
      org.opencontainers.image.vendor="Qertum" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

# The app-level /health and /alive endpoints are Development-only, so this asks
# runit for process status instead (see healthcheck.sh). start-period gives
# all five .NET processes room to boot before failures count against retries.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=5 \
    CMD ["/usr/local/bin/healthcheck.sh"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
