# syntax=docker/dockerfile:1

# One image for every Qertum service, started with SERVICE=<name> (see entrypoint.sh).
# Used by deploy/multi-container/docker-compose.yml: one container per service. The
# single-container image (deploy/single-container) stays for homelab setups.

FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:747cbade5bfd918a175ac32f8f1d931edec2c7d0d5397a3de72eaef1ac1f66d2 AS build
WORKDIR /src

# Copy the whole repo: the projects share many references and a partial copy is brittle.
COPY . .

RUN dotnet publish Qertum.IdentityService/Qertum.IdentityService.csproj -c Release -o /app/identityservice && \
    dotnet publish Qertum.ApiService/Qertum.ApiService.csproj         -c Release -o /app/apiservice && \
    dotnet publish Qertum.AcmeService/Qertum.AcmeService.csproj       -c Release -o /app/acmeservice && \
    dotnet publish Qertum.EstService/Qertum.EstService.csproj         -c Release -o /app/estservice && \
    dotnet publish Qertum.Web/Qertum.Web.csproj                       -c Release -o /app/webfrontend && \
    dotnet publish Qertum.QueueConsumer/Qertum.QueueConsumer.csproj   -c Release -o /app/queueconsumer && \
    dotnet publish Qertum.RestoreCheck/Qertum.RestoreCheck.csproj     -c Release -o /app/restorecheck

FROM mcr.microsoft.com/dotnet/aspnet:10.0-resolute@sha256:535673eb0bf091deebbfefe0ab17dae903f86e49c9687df06448823435ccbc3c AS runtime

# tpm2-tools: LocalTpm key custody. Redis is its own container, not part of this image.
# The resolute base ships /usr/bin/pebble (a Go service manager) that nothing here runs; it only adds
# Go stdlib findings, so remove it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tpm2-tools \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/bin/pebble

COPY --from=build /app /app
COPY deploy/multi-container/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY deploy/multi-container/healthcheck.sh /usr/local/bin/healthcheck.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/healthcheck.sh && mkdir -p /data /run/est

# Shared state for every container: database, Data Protection key ring, issuer key files, audit logs
# and the identity store (/data/identity). Same layout as the single-container image.
VOLUME ["/data"]

# web 8080 | identity 8081 | api 8082 | acme 8083 | est 8084 (queueconsumer has no endpoint)
EXPOSE 8080 8081 8082 8083 8084

# OCI image metadata. VERSION is passed by the publisher (`--build-arg VERSION=<tag>`).
ARG VERSION=dev
LABEL org.opencontainers.image.title="Qertum services" \
      org.opencontainers.image.description="Self-hosted post-quantum certificate authority, one image per service (SERVICE selects it). Includes EST." \
      org.opencontainers.image.source="https://github.com/Qertum/qertum" \
      org.opencontainers.image.url="https://github.com/Qertum/qertum/wiki" \
      org.opencontainers.image.documentation="https://github.com/Qertum/qertum/wiki" \
      org.opencontainers.image.vendor="Qertum" \
      org.opencontainers.image.version="${VERSION}"

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=5 \
    CMD ["/usr/local/bin/healthcheck.sh"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
