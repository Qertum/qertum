# Multi-container deployment

One container per Qertum service (identity, API, web, ACME, EST, queue consumer) plus Redis, on
one host, all from the same image. Pick it over [`deploy/single-container`](../single-container/README.md)
when you want EST, want ACME and EST reachable without exposing the API, identity or web UI, or want
TLS terminated per service.

It is **not** scale-out. API, ACME, EST and the queue consumer share one SQLite file and in-process
channels, so run exactly one of each. Redundancy is not supported yet.

## Quick start

1. Get the image: pull it from your registry (CI pushes `qertum-services:latest` and
   `qertum-services:<git-sha>` next to the single-container image), or build it:
   `docker build -f deploy/multi-container/Dockerfile -t qertum-services:dev .`
2. `cp deploy/multi-container/.env.example deploy/multi-container/.env` and fill in the required
   values (below).
3. `docker compose -f deploy/multi-container/docker-compose.yml --env-file deploy/multi-container/.env up -d`

Services start in dependency order on health: Redis and identity, then the API, then web, ACME, EST
and the queue consumer. Browse to `http://<QERTUM_HOST>:8080` and log in as `admin` (password from
`SEED_ADMIN_PASSWORD`, or `password` if unset, which the first login forces you to change).

| Variable | Required | Meaning |
|---|---|---|
| `QERTUM_IMAGE` | yes | Image reference, e.g. `registry.example.lan:5000/qertum-services:latest` |
| `QERTUM_HOST` | yes | Public host name or IP that browsers, ACME/EST clients **and the other containers** use, exactly as users type it (no NAT, DNS alias or other name in between; a different browser address fails sign-in with ID2043); advertised in every URL. Not `localhost`: inside a container that is the container itself, so `apiservice` and `webfrontend` refuse to start (exit 64). On Docker Desktop use `host.docker.internal` for a local trial |
| `QERTUM_EST_TLS_CERT`, `QERTUM_EST_TLS_KEY` | yes | Host paths of the EST server certificate chain and key (PEM) |
| `QERTUM_DATA` | no | Host path or volume for `/data` (default: named volume `qertum-data`) |
| `QERTUM_SCHEME` | no | `http` (default) or `https` for web, identity and API when a proxy terminates TLS for them. `https` also has those three take the client's scheme and address from the proxy's `X-Forwarded-Proto`/`X-Forwarded-For`, so their ports must be reachable by the proxy only. Never for ACME or EST, which never trust those headers. With `http` the web, identity and API containers log a warning at every start, and the API and web UI log one again on startup: sign-in, tokens and the admin password are then unencrypted. |
| `WEB_PORT`, `IDENTITY_PORT`, `API_PORT`, `ACME_PORT`, `EST_PORT` | no | Advertised and published ports (defaults 8080–8084). Containers always listen on 8080–8084 inside |
| `ACME_SCHEME` | no | `http` (default) or `https`, the scheme ACME advertises. `https` only when the acme container terminates TLS itself (see below) |
| `SEED_ADMIN_PASSWORD` | no | First-run admin password |

## Layout

- Container names are `qertum-<service>` (`qertum-apiservice`, …, `qertum-cache`). The backup
  wrappers depend on them.
- Every Qertum container mounts the same `/data`: database, Data Protection key ring, issuer key
  files, audit logs and the identity store (`/data/identity`). The layout is the same as the single
  container's, so a single-container volume can be mounted here unchanged (see below).
- All containers share `/data`, so the queue consumer sees the identity service's audit directory and its chain is in the checkpoint; if you mount the identity store elsewhere set `AuditLog__Checkpoint__IdentityDirectory` on `qertum-queueconsumer`.
- Audit lines are hash-chained; the `AuditCheckpoint` webhook gives an off-host anchor for `qca audit verify`. How to use it and what it cannot detect is in the single-container README under "Tamper-evident audit log".
- If a CA key is compromised, follow [Issuer Compromise Recovery](https://github.com/Qertum/qertum/wiki/Issuer-Compromise-Recovery); a restore from backup does not help.
- Step-up (a second factor for the most sensitive operations) works the same way as in the single container: set `Identity__StepUp__Enabled=true` on `qertum-apiservice` and use an identity provider that emits `acr` and `auth_time`. See "Require MFA for sensitive operations" in the single-container README and the claims contract in [Identity Providers](https://github.com/Qertum/qertum/wiki/Identity-Providers).
- Redis is its own container on the internal network and is never published. It holds only
  regenerable entries (CRL, ACME nonces).
- Published ports: web, identity, API, ACME and EST. The queue consumer has none. To expose only
  ACME and EST on a wider network, publish those two on that interface and leave the rest on the
  LAN (change the `ports:` entries to `"<ip>:<port>:<container port>"`).

## EST: TLS terminated by the service

EST re-enrollment (`/simplereenroll`) uses the client certificate as the credential, so the EST
container terminates TLS itself and a proxy in front must forward the client certificate or pass TCP
through. Mount a PEM certificate chain and key (`QERTUM_EST_TLS_CERT`, `QERTUM_EST_TLS_KEY`). The
key must be readable by UID 1654, for example `chown 1654 tls.key && chmod 400 tls.key`. The service
**refuses to start** without both files; it never falls back to plain HTTP. Clients need to trust
the issuer of that server certificate. Qertum does not issue it (bootstrap circle): use your
existing PKI or a self-signed certificate for a lab.

## ACME: no TLS-terminating proxy

ACME must **not** sit behind a proxy that terminates TLS. ACME clients sign the request URL into every
request and the service compares it with the scheme and host it sees, so behind such a proxy it answers
"URL mismatch". This is a requirement, not something to configure around (a proxy for web, identity and
API is fine). By default ACME speaks plain HTTP on `ACME_PORT`, which is what ACME clients accept on a
trusted network. To have it serve TLS itself, add a compose override for `acmeservice` that sets
`ASPNETCORE_URLS=https://0.0.0.0:8083` (keep the port), `Kestrel__Certificates__Default__Path` and
`Kestrel__Certificates__Default__KeyPath`, and mounts the PEM files, and set `ACME_SCHEME=https` so the
directory, the order links and the enrollment wizard advertise `https`.

## TPM key custody

`LocalTpm` needs the TPM device and its group in **every** container that builds the key ring, so
they are passed by an opt-in override that lists all six services:

```sh
TPM_DEVICE=/dev/tpmrm0 TPM_GROUP=105 docker compose \
  -f deploy/multi-container/docker-compose.yml -f deploy/multi-container/docker-compose.tpm.yml \
  --env-file deploy/multi-container/.env up -d
```

Run once on real hardware, 2026-10-20: one x86_64 TPM 2.0 (`/dev/tpmrm0`), Ubuntu 26.04, Docker 29 (see "Manual verification"). The single-container image was run on the same machine on 2026-10-23 (see its README). Other TPMs, firmware TPMs, arm64 and a cleared or replaced TPM have not been tried.

## Backup and restore

```sh
deploy/multi-container/backup.sh [output-dir]          # PowerShell: backup.ps1
deploy/multi-container/restore-test.sh [--image <ref>] <archive|dir>   # PowerShell: restore-test.ps1 [-Image <ref>]
deploy/multi-container/restore.sh <archive>            # PowerShell: restore.ps1
```

`backup` and `restore` stop every Qertum container except `qertum-apiservice` (which supplies the
volume), delegate to the single-container scripts unchanged, and restart the others on any exit,
including a failure or declining the restore prompt. Redis keeps running. `restore-test` stops
nothing; its offline check uses the image of `qertum-apiservice` unless you pass `--image`. The status files, manifest, offline check and exit codes are the ones of the single-container scripts, described under
[Backup and Restore](https://github.com/Qertum/qertum/wiki/Backup-and-Restore); the `.ps1` twins need PowerShell 7 (`pwsh`); Windows PowerShell 5.1 is not supported.

## Moving from the single container

1. Take a backup with the single-container `backup.sh`, then stop that container.
2. Point `QERTUM_DATA` at the same host path and `up -d`. The layout is identical (identity data is
   already under `/data/identity`), so nothing migrates.
3. Keep `QERTUM_HOST` and the ports the same so the issuer and redirect URIs do not change.

## Manual verification

No automated test boots this stack; `MultiContainerContractTests` pins the files' shape only. The
manual run, last done 2026-10-08 (Docker Desktop on macOS, arm64, `QERTUM_HOST=host.docker.internal`,
a throwaway self-signed EST certificate):

- Image builds; a missing, unknown or `localhost`-hosted `SERVICE` exits 64; `estservice` without its
  certificate exits 64; processes run as `app`.
- `up -d`: all seven containers healthy in dependency order. Web redirects to the identity
  authorize endpoint with the right redirect URI, identity discovery and the ACME directory advertise
  the public URLs, `/crl` answers 503 before onboarding.
- EST: `openssl s_client` to port 8084 shows the server certificate, plain HTTP to 8084 is refused,
  `/.well-known/est/cacerts` answers 503 before onboarding. `docker port qertum-cache` prints nothing.
- `backup.sh`, then `restore-test.sh` (exit 0, 11 files), then `restore.sh` answering `n` (aborts,
  every container restarted) and `y` (restores, every container healthy again).
- A volume initialised by the single-container image starts under compose with the same identity
  signing key (same `kid` in the JWKS) and no re-onboarding.

TPM override, run 2026-10-20 on one x86_64 TPM 2.0 (Ubuntu 26.04 host, Docker 29, `QERTUM_HOST` a name every container resolves):

- The API, identity and queue consumer processes keep the TPM group (`Groups: 987 1654` in `/proc/<pid>/status`) and the status endpoint reports `tpmAvailable: true`. Before the entrypoint kept the groups it dropped them and reported `false`.
- A CA onboarded on the file key, then `POST /v1/secret-storage/migrate` to `LocalTpm` and a restart of every container, plus `IdentityService__SecretStorageProvider=LocalTpm` for identity: both write `secret-storage/tpm-sealed.blob`. The certificate issued before the migration still yields its private key, a new one is issued, the CRL is served.
- `backup.sh` then `restore-test.sh` exits 2 ("could not test": the archive matches its manifest but the data cannot be opened without the TPM). `Qertum.RestoreCheck` on a copy of `/data` with the device and group passed passes all four checks, and without the device cannot open it. `restore-test.sh` passes no device, so it cannot test a TPM-sealed backup.
- 2026-10-23, same machine, single-container image `alpha-02` with `--device /dev/tpmrm0 --group-add <group>`: `tpmAvailable: true` as non-root; a CA on the file key, migrate to `LocalTpm`, restart (keys issued before and after migration downloadable, CRL served), migrate back to `LocalFileKey`, restart (still readable, a new certificate issued; `tpm-sealed.blob` stays, as documented). Data left on `LocalTpm` and started without the device exits with `'tpm2_createprimary ...' ... Failed to open specified TCTI device file /dev/tpmrm0`; started again with the device it recovers. Data on the file key starts without a device.
- Not run: a cleared or replaced TPM, other hardware, the `.ps1` wrappers, and an
  EST `/simplereenroll` with a client certificate.

Security scan, run 2026-10-29 (Docker Desktop on macOS, arm64, image built from source, ports 9080–9084, an ECDSA P-256 root onboarded through the API, one EST username and password):

- EST: `cacerts` and `csrattrs` answer 200; `simpleenroll` without credentials, with a wrong password or with a malformed `Authorization` header answers 401, a CSR that is not base64 or not a CSR answers 400, a valid one 202 (waiting for approval); `simplereenroll` with only a password answers 401; plain HTTP to 8084 is refused; more than 20 attempts a minute answer 429.
- TLS on 8084 (testssl.sh): TLS 1.2 and 1.3 only, no known protocol weakness. TLS 1.2 still offers CBC suites, which testssl flags as "potentially vulnerable" to LUCKY13; restricting them would refuse older EST clients, so it is left as is.
- Nikto, OWASP ZAP baseline and sqlmap (OIDC token and authorize endpoints, ACME renewal-info) found nothing beyond missing browser headers (`X-Content-Type-Options`, `Referrer-Policy`, framing protection), which every service has sent since this run. The API rate limit has also been per caller since this run; before, one caller could use it up for everyone. ZAP still warns that the CSP has no `default-src` or `script-src`: no script policy for the web UI yet.

## Two-person approval

Optional and off by default: an administrator switches it on in Settings → Issuance (or `qca approvals switch on`, or `PUT /v1/settings/two-person-approval`). While it is on, downloading someone else's private key, changing issuers, executing a bulk revoke and publishing an issuance policy each need a second administrator's approval, spent as a one-use grant within a time window. **With a single administrator those operations cannot be done until it is switched off again** (switching it off needs no approval). The time limits are `Approvals__GrantWindowMinutes` (default `15`, 1 to 1440), `Approvals__RequestTtlHours` (default `24`, 1 to 168) and `Approvals__RetentionDays` (default `365`, 1 to 3650), set on `the API service and the queue consumer`.
