# syntax=docker/dockerfile:1

# Standalone image for the Qertum identity provider. Unlike deploy/single-container,
# this is one process with one entrypoint: the IdP is independently deployable and
# shares nothing with the CA application except an issuer URL.

# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:de4fe90a98845d75910b9769662465c84de1a934665c431279d1382b2bddc02b AS build
WORKDIR /src

# Copy the whole repo. Qertum.IdentityService references Qertum.ServiceDefaults, and
# a partial copy is brittle as the solution grows.
COPY . .

RUN dotnet publish Qertum.IdentityService/Qertum.IdentityService.csproj -c Release -o /app

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/aspnet:10.0-resolute@sha256:76383bc2150de411212238b0fb3cd83239ce4060f5a64d07be88624d8441d1e8 AS runtime
WORKDIR /app

# The aspnet base image ships no HTTP client, and the app's /health endpoint is
# Development-only (see Qertum.ServiceDefaults), so the healthcheck needs curl to
# probe the discovery document instead.
# The resolute base ships /usr/bin/pebble (a Go service manager) that nothing here runs; it only adds
# Go stdlib findings, so remove it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl tpm2-tools \
 && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/bin/pebble

COPY --from=build /app .
COPY deploy/identity/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# All mutable state lives here: users.json, clients.json, identity.db, keys/.
# Losing keys/ invalidates every live session — back this volume up.
ENV IdentityService__DataPath=/data
RUN mkdir -p /data
VOLUME ["/data"]

ENV ASPNETCORE_URLS=http://0.0.0.0:8080
EXPOSE 8080

# OpenIddict builds every advertised endpoint URL (authorization, token, jwks_uri,
# the device verification_uri, the /login challenge redirect) from the *incoming
# request's* scheme and host — only "iss" comes from IdentityService:Authority.
# Behind a TLS-terminating proxy the request arrives over http, so without this the
# discovery document advertises http:// URLs under an https:// issuer. This switch
# makes ASP.NET Core honour X-Forwarded-For and X-Forwarded-Proto; the original host
# comes from the Host header, which the proxy must preserve.
ENV ASPNETCORE_FORWARDEDHEADERS_ENABLED=true

# Probing the discovery document also proves OpenIddict initialized.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8080/.well-known/openid-configuration -o /dev/null || exit 1

# Starts as root to fix volume ownership, then runs the IdP as the unprivileged `app` user.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
