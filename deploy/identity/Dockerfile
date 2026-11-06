# syntax=docker/dockerfile:1

# Standalone image for the Qertum identity provider. Unlike deploy/single-container,
# this is one process with one entrypoint: the IdP is independently deployable and
# shares nothing with the CA application except an issuer URL.

# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:212fe4cb74627d5adf9817a4088906ae3edff1bd853bb27565d4b46731efe61e AS build
WORKDIR /src

# Copy the whole repo. Qertum.IdentityService references Qertum.ServiceDefaults, and
# a partial copy is brittle as the solution grows.
COPY . .

RUN dotnet publish Qertum.IdentityService/Qertum.IdentityService.csproj -c Release -o /app

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/aspnet:10.0-resolute@sha256:c159e6c30ed39d4728d3d9f07f26dca10945896f7a072949cb9786ebcfea609d AS runtime
WORKDIR /app

# The aspnet base image ships no HTTP client, and the app's /health endpoint is
# Development-only (see Qertum.ServiceDefaults), so the healthcheck needs curl to
# probe the discovery document instead.
# The resolute base ships /usr/bin/pebble (a Go service manager) that nothing here runs; it only adds
# Go stdlib findings, so remove it.
# apt-get upgrade applies Ubuntu's security updates published since Microsoft last rebuilt the digest-pinned base
# (1.0.0-rc6: apt 3.2.0 had a fixable HIGH, CVE-2026-109518, that the publish-image Trivy gate refuses).
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends curl tpm2-tools \
 && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/bin/pebble

COPY --from=build /app .
COPY LICENSE THIRD-PARTY-NOTICES.txt /usr/share/doc/qertum/
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
# Behind a TLS-terminating proxy the request arrives over http, so without
# X-Forwarded-Proto the discovery document advertises http:// URLs under an https://
# issuer. entrypoint.sh honours X-Forwarded-For/-Proto only when QERTUM_TRUSTED_PROXIES
# names the proxy (trusting them from everyone would let any client claim https); the
# original host comes from the Host header, which the proxy must preserve.

# Probing the discovery document also proves OpenIddict initialized.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8080/.well-known/openid-configuration -o /dev/null || exit 1

# Starts as root to fix volume ownership, then runs the IdP as the unprivileged `app` user.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
