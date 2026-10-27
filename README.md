# Qertum

A self-hosted certificate authority with post-quantum support. Issue, track, renew and revoke X.509
certificates through a web UI, a REST API, a command line, or standard ACME and EST clients. Storage is
SQLite: no external database, message broker or cloud service is needed.

> **Release candidate (1.0.0-rc1.1).** Open for testing: pin an exact image tag and do not use it in production yet. The [support and compatibility policy](SUPPORT.md) takes effect with 1.0.0.

## Quick start

```bash
docker run -d --name qertum \
  -e QERTUM_HOST=<host-name-or-ip> \
  -e IdentityService__SeedAdminPassword='choose-a-strong-password' \
  -p 8080:8080 -p 8081:8081 -p 8082:8082 -p 8083:8083 \
  -v qertum-data:/data \
  --restart unless-stopped \
  qertum/qertum:1.0.0-rc1.1
```

Open `http://<host-name-or-ip>:8080`, sign in as `admin` and follow the onboarding to create or import your
root CA. The ACME directory is at `http://<host-name-or-ip>:8083/acme/directory`. Published host ports must
equal the container ports, and `QERTUM_HOST` must be the name or IP your clients use to reach the host. Browse to Qertum with exactly the text you gave as `QERTUM_HOST`: `localhost`, `127.0.0.1` and the machine's LAN IP are different values, and a browser address that differs from it fails sign-in with `The specified 'redirect_uri' is not valid for this client application` (ID2043).

The single container has no EST endpoint. For EST, or to expose only ACME and EST, use the multi-container
layout in [`deploy/multi-container/`](deploy/multi-container/README.md).

## Images

Two multi-architecture images (linux/amd64 and linux/arm64), identical on three registries:

| Deployment | Docker Hub | Quay.io | GitHub Container Registry |
|---|---|---|---|
| Single container | `qertum/qertum` | `quay.io/qertum/qertum` | `ghcr.io/qertum/qertum` |
| One container per service | `qertum/qertum-services` | `quay.io/qertum/qertum-services` | `ghcr.io/qertum/qertum-services` |

## What it does

- **Request lifecycle** with approval, renewal and asynchronous revocation, every step audit-logged in a
  tamper-evident log. Optional two-person approval for the most sensitive operations.
- **ACME (RFC 8555)** with `http-01` and `dns-01`, including wildcards and external account binding, and
  **EST (RFC 7030)** for devices, in the multi-container layout.
- **Post-quantum ready**: RSA and ECDSA alongside ML-DSA, SLH-DSA, ML-KEM, paired classical and
  post-quantum certificates, and composite ML-DSA, with a staged enforcement policy that can steer an
  organisation off classical keys.
- **Issuance policies and templates** that govern every path (web, API, CLI, ACME, EST), and role-based
  permissions.
- **Issuer hierarchy**: an offline root with online intermediates, rollover and trust-bundle export.
- **Revocation publishing**: a CRL at `/crl` and an OCSP responder at `/ocsp`.
- **Webhooks** with HMAC signatures and retries, and metrics through OpenTelemetry.

## Keep the CA key safe

Back up `/data`: it holds the CA private key, and losing it loses the CA. Clients reject Qertum
certificates until the root is installed as a trust anchor on each of them. Exporting a CA key is possible
for administrators but is not a safe way to manage one; keep a production root offline.

## Documentation

The [wiki](https://github.com/Qertum/qertum/wiki) covers installing, configuring and operating Qertum:

- [Single Container](https://github.com/Qertum/qertum/wiki/Single-Container) and
  [Multi Container](https://github.com/Qertum/qertum/wiki/Multi-Container)
- [Using the Web UI](https://github.com/Qertum/qertum/wiki/Using-the-Web-UI) and
  [Using the REST API](https://github.com/Qertum/qertum/wiki/Using-the-REST-API)
- [Backup and Restore](https://github.com/Qertum/qertum/wiki/Backup-and-Restore),
  [Upgrading](https://github.com/Qertum/qertum/wiki/Upgrading) and
  [Troubleshooting](https://github.com/Qertum/qertum/wiki/Troubleshooting)
- [Identity Providers](https://github.com/Qertum/qertum/wiki/Identity-Providers) and
  [Issuer Compromise Recovery](https://github.com/Qertum/qertum/wiki/Issuer-Compromise-Recovery)

What a version number promises, which releases get security fixes and where to ask for help is in the
[support and compatibility policy](SUPPORT.md).

Each deployment also has its own guide next to its compose files:
[`deploy/single-container/`](deploy/single-container/README.md),
[`deploy/multi-container/`](deploy/multi-container/README.md) and
[`deploy/identity/`](deploy/identity/README.md).

## Building from source

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download) and Docker.

```bash
dotnet build Qertum.sln
dotnet test Qertum.sln
```

To run the whole stack locally, see [Local Development](https://github.com/Qertum/qertum/wiki/Local-Development).

## Security, contributing and license

- Report vulnerabilities privately: [SECURITY.md](SECURITY.md).
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md), [Code of Conduct](CODE_OF_CONDUCT.md).
- MIT, see [LICENSE](LICENSE).
