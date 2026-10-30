# syntax=docker/dockerfile:1

# Single-container image bundling the entire Qertum stack (the five services the
# Aspire AppHost normally orchestrates) into one container, supervised by runit.
# Intended for homelab / Unraid deployments. See deploy/single-container/README.md.

# ---------------------------------------------------------------------------
# Build stage: restore + publish each runtime service into its own /app folder.
# ---------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:de4fe90a98845d75910b9769662465c84de1a934665c431279d1382b2bddc02b AS build
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
# Redis stage: only the server binary is taken from the official image, pinned by digest, so
# the shared cache runs the same Redis major as the AppHost and the tests (Ubuntu 24.04's
# redis-server package is 7.0). No third-party apt repository is added to the runtime image.
# See "Bumping the base image" in the README.
# ---------------------------------------------------------------------------
FROM redis:8.6@sha256:372207266325710e75866163a505d18ac0362372c8bf02ad5a0cf0b3c8bbc23e AS redis

# ---------------------------------------------------------------------------
# Runtime stage: ASP.NET runtime + runit running Redis and the five processes.
# ---------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/aspnet:10.0-resolute@sha256:76383bc2150de411212238b0fb3cd83239ce4060f5a64d07be88624d8441d1e8 AS runtime

# runit supervises Redis and the five .NET processes (it pulls in no Python, unlike the
# supervisord it replaced); tini is PID 1 and reaps orphans; tpm2-tools is for the LocalTpm
# secret-storage provider.
# The resolute base ships /usr/bin/pebble (a Go service manager) that nothing here runs; it only adds
# Go stdlib findings, so remove it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends runit tini tpm2-tools \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/bin/pebble

# The shared cache's server (from the digest-pinned redis stage above).
COPY --from=redis /usr/local/bin/redis-server /usr/local/bin/redis-server

COPY --from=build /app /app
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
