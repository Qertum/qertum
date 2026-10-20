# Qertum single-container image

Bundles five of the six services the Aspire AppHost orchestrates (`identityservice`,
`apiservice`, `acmeservice`, `webfrontend`, `queueconsumer`) into **one** Docker image,
supervised by `runit` (Redis and the five services each restart when they exit). Built for homelab / Unraid deployments where running the
Aspire manifest — six service containers plus Redis — is overkill and the shared SQLite
DB / CA files / Data Protection keyring are easier to keep on a single volume.

Not included:

- **`estservice` (EST, RFC 7030).** The image has no EST endpoint. EST re-enrollment also
  needs TLS terminated by Kestrel itself (the client certificate is the credential), which
  this plain-HTTP, port-per-service layout does not provide.

> For the enterprise layout (one container per service, EST included) see
> [`../multi-container`](../multi-container/README.md). The two share the `/data` layout.

## What runs inside

| Service | Internal port | Exposed for |
|---|---|---|
| `webfrontend` (Blazor UI) | 8080 | browsers |
| `identityservice` (OpenIddict IDM) | 8081 | browser OIDC login |
| `apiservice` (REST API) | 8082 | optional direct API/CLI access |
| `acmeservice` (RFC 8555) | 8083 | certbot / cert-manager |
| `queueconsumer` (worker) | — | none (background only) |
| `redis` (shared cache) | 6379 (loopback) | none (internal only) |

Redis holds the published CRL, the delta CRL and ACME nonces for every process. It binds to
loopback, keeps nothing on disk, and is safe to lose: CRLs are regenerated on the next request
or scheduled refresh.

All five share `/data`, which holds:

```
/data/certificate-requests.db              shared app DB (api/acme/consumer)
/data/CaData/ca.{key,pem}                  root CA keypair + cert
/data/DataProtection-Keys/                 encryption keyring (must persist!)
/data/secret-storage/, secret-storage.json key that wraps the keyring, and which provider made it
/data/audit-logs/*.clef                    audit log
/data/identity/identity.db                 IDM store
/data/identity/{users,clients,roles}.json  IDM users, OIDC clients, role catalog
/data/identity/keys/                       IDM signing/encryption certs (rotated automatically)
/data/identity/secret-storage/             key that wraps the IDM certs in keys/
/data/identity/audit-logs/*.clef           IDM audit log (user and role administration)
/data/.api-introspection-secret            generated qertum-api client secret (the name is
                                           historical; nothing uses introspection)
```

Images built before 2026-09-23 kept `roles.json`, the IDM's `secret-storage/` and its audit
log inside the container rather than on `/data`, so re-creating the container lost them and
signed everyone out. The current entrypoint moves any of those still in the container onto
`/data` on first start. What an earlier re-creation already lost cannot be recovered.

**Back up `/data`. Losing it loses your CA private key.** See [Backup & restore](#backup--restore) below.

## Configuration

The entrypoint derives all cross-service wiring from a few env vars:

| Env var | Default | Notes |
|---|---|---|
| `QERTUM_HOST` | `localhost` | **Set this** to the Unraid host IP/hostname. Used for the browser-facing OIDC authority and ACME base URL. |
| `QERTUM_API_INTROSPECTION_SECRET` | auto-generated | `qertum-api` client secret seeded into IdentityService's `clients.json`. Leave unset to auto-generate + persist on `/data`. |
| `IdentityService__SeedAdminPassword` | `password` | Password for the `admin` user seeded on first run. Read only while `/data`'s `users.json` is absent. Left unset, the account is flagged: the first login can only change the password or sign out, and no token is issued for it, until the password is changed. |
| `WEB_PORT` / `IDENTITY_PORT` / `API_PORT` / `ACME_PORT` | 8080/8081/8082/8083 | Internal listen ports. |
| `ASPNETCORE_ENVIRONMENT` | `Production` | Keeps Scalar/OpenAPI and health endpoints locked down. |
| `Identity__StepUp__Enabled` | `false` | Require a second factor for the most sensitive operations (private-key download, CA and issuer changes, bulk execute, role grants, policy publish). Needs an **external** identity provider that puts `acr` and `auth_time` in the access token; see [Require MFA for sensitive operations](#require-mfa-for-sensitive-operations). The built-in identity service does not emit them. |
| `IdentityService__SecretStorageProvider` | unset | `LocalFileKey` or `LocalTpm` for the IDM's own certificates; unset keeps what `/data/identity` records. See [TPM-backed secret storage](#enabling-tpm-backed-secret-storage). |
| `IdentityService__CertificateLifetimeDays` | `1825` | Validity window for the IDM's own signing/encryption certificates. Applies to newly created ones only. |
| `IdentityService__CertificateRenewBeforeDays` | `90` | How far ahead of expiry a replacement is created, and therefore the overlap window. Must exceed your longest refresh-token lifetime. |

ApiService validates bearer tokens directly as standard OIDC JWTs against the
issuer (no introspection round-trip, no shared secret) — the entrypoint points it
at IdentityService via `Identity__Authority=http://<QERTUM_HOST>:<IDENTITY_PORT>`,
the same host:port pair as `IdentityService__Authority`.

### Webhook destinations

Webhook delivery permits public HTTP(S) receivers by default. It blocks private, loopback,
link-local, multicast, unspecified, and known cloud metadata addresses unless an administrator
adds an exact internal rule; link-local and metadata addresses remain blocked even with a rule.
The queue consumer waits for ApiService to initialize policy state. It checks the final URL and
every DNS answer on each attempt. Redirects and proxies are disabled.

Set a JSON baseline in ApiService configuration (or environment variables using `__` in place
of `:`):

```json
{
  "WebhookDestinationPolicy": {
    "PublicMode": "ListedPublic",
    "Rules": [
      {
        "Kind": "Internal",
        "Scheme": "http",
        "Host": "receiver.lan",
        "Port": 8088,
        "AllowedIpAddresses": ["192.168.1.20"]
      }
    ]
  }
}
```

`AnyPublic` with an empty rule list is the shipped default. `ListedPublic` requires explicit
public-origin rules. Admins can disable a JSON rule without editing the file; this override
survives restart. Removing the JSON rule removes its active baseline effect.

Admins can manage rules on the Webhooks page or through CLI:

```bash
qca webhooks destinations list
qca webhooks destinations add --url http://receiver.lan:8088 --ip 192.168.1.20
qca webhooks destinations add --url https://hooks.example.com --public
qca webhooks destinations mode listed-public
qca webhooks destinations disable <rule-id>
```

Only administrators can change destination policy. A user with `settings.edit` can manage webhook
subscriptions but cannot expand allowed destinations. Existing deliveries to internal receivers
stop until an exact rule is added. Plan these rules before upgrading an installation with internal
webhook receivers.

Because traffic is plain HTTP (direct port exposure), the entrypoint also sets
`IdentityService__DisableTransportSecurity=true`,
`OpenIdConnect__RequireHttpsMetadata=false`, and
`Identity__RequireHttpsMetadata=false` — opt-in flags that let OpenIddict, the
Web OIDC client, and ApiService's JWT validation all work over HTTP. If you later
front the container with a TLS reverse proxy, set those three to
`false`/`true`/`true` and point `QERTUM_HOST` at the proxy hostname.

## Run on Unraid (direct port exposure)

```bash
docker run -d --name qertum \
  -e QERTUM_HOST=192.168.1.50 \
  -p 8080:8080 -p 8081:8081 -p 8082:8082 -p 8083:8083 \
  -v /mnt/user/appdata/qertum:/data \
  <REGISTRY>/qertum:latest
```

Then browse to `http://192.168.1.50:8080`. On first run log in as `admin` with whatever you
set `IdentityService__SeedAdminPassword` to, or with `password` if you left it unset — in
that case the provider immediately requires you to pick a new one, and nothing else in the
stack works until you do.

Point ACME clients at `http://192.168.1.50:8083/acme/directory` — the enrollment wizard shows
the same URL with certbot, acme.sh and cert-manager examples. Before an `http-01`
challenge can validate, add the networks the CA may connect to under Settings — the
allowlist starts empty, and empty means no `http-01` challenge validates. `dns-01` does not
use it.

## TLS / exposing beyond the LAN

By default every service speaks plain HTTP, including the OIDC authority — fine
on a trusted LAN, not fine if this ever needs to be reachable from the internet
or an untrusted network (bearer tokens and ACME account keys go over the wire in
the clear).

**Why per-port, not per-subdomain:** the entrypoint bakes `QERTUM_HOST` +
each service's port into the URLs it advertises (`IdentityService__Authority`,
`Acme__BaseUrl`, the web redirect URI) — there's a single hostname shared by all
four services, differentiated only by port. So a reverse proxy in front has to
preserve that same `host:port` shape browsers/ACME clients already expect,
rather than remapping to subdomains or a single port 443 (that would need
per-service hostname plumbing the entrypoint doesn't support today). Concretely: proxy `ca.example.com:8080-8082` to the
container's `8080-8082`, terminating TLS at the proxy.

**ACME is not proxied.** ACME must not sit behind a TLS-terminating proxy: clients sign the request URL into
every request and the service compares it with the scheme and host it sees, so behind a proxy it answers "URL
mismatch". Leave port `8083` out of the proxy and let ACME clients reach it directly over plain HTTP.

To do this:

1. Put a TLS-terminating reverse proxy (Caddy, Traefik, nginx) in front, listening
   on the same three ports (web, identity, API) and forwarding to the container. See
   [`Caddyfile.example`](./Caddyfile.example) for a starting point — add it as a
   second service in your compose file, on the same network as `qertum`.
   - If using Caddy's automatic HTTPS, it needs port 80 reachable for the HTTP-01
     challenge (or configure DNS-01) even though the site blocks listen on
     8080-8082 — open that too, or supply your own certs.
2. Point `QERTUM_HOST` at the proxy's public hostname instead of the LAN IP.
3. Flip the three opt-in HTTP-transport flags back to their secure defaults:
   `IdentityService__DisableTransportSecurity=false`,
   `OpenIdConnect__RequireHttpsMetadata=true`, and
   `Identity__RequireHttpsMetadata=true` (ApiService's own JWT/metadata validation).
4. Add `Services__webfrontend__https__0=https://<QERTUM_HOST>:<WEB_PORT>` as an
   extra environment variable on the `qertum` service. `entrypoint.sh` only ever
   exports the `http` scheme variant (`Services__webfrontend__http__0`); without
   this override, `ClientSeedHostedService` keeps registering an `http://`
   redirect URI even though browsers now reach the app over `https://`, and OIDC
   login will fail with a redirect-URI mismatch. No manual `clients.json` edit is
   needed — `ClientSeedHostedService` re-syncs from this var on every start.
   - `ClientSeedHostedService` only reads `Services__webfrontend__*` when
     `IdentityService__EnableServiceDiscoveryRedirectUris` is true (it defaults to
     Development only). `entrypoint.sh` exports it as `true` for this deployment;
     leave it alone unless you intend to manage `clients.json` by hand.
5. Re-deploy.


## IDM key rotation

The certificates in `/data/identity/keys/` are rotated automatically: once the newest is
within `IdentityService__CertificateRenewBeforeDays` of expiry, the next **container start**
creates a replacement beside it. Every still-valid certificate stays published in the JWKS
document, so tokens signed with the retiring key keep validating through the overlap and
nobody is signed out. Expired files are left on disk, unused.

Rotation is checked at start-up only. A container that runs for longer than the renewal
window without restarting will not rotate — restart it (or redeploy) at least once inside
that window. With the 90-day default this is not a constraint any normal update cadence hits.

## Runs without root

The container starts as root only long enough to make `/data` writable for the unprivileged
`app` user (UID 1654, from the .NET base image), then re-executes the entrypoint as that user.
Redis, runit and all five .NET processes run as `app`. A `/data` volume written by an older
image that ran as root is re-owned once, on the first start; the log says so. If your storage
cannot be re-owned (some NFS exports squash root), the log warns and the services fail to write;
fix the export, or start the container with `--user 1654:1654` against a volume that user can write.

## Require MFA for sensitive operations

With an external identity provider (OIDC), Qertum can demand a recent second factor for the operations that do the most harm
if a session is stolen: downloading a private key or PFX, generating, importing or replacing the CA, creating or changing
issuers, executing a bulk operation, migrating secret storage, changing role grants and publishing an issuance policy.
It is off by default. Turn it on with `Identity__StepUp__Enabled=true` on the API service.

The contract is two claims on the **access token**; Qertum reads nothing else, so the identity provider is configured to
emit them (the contract, the settings and a tested Keycloak recipe are in [Identity Providers](https://github.com/Qertum/qertum/wiki/Identity-Providers)):

| Claim | Meaning | Setting |
|---|---|---|
| `acr` | authentication class; one of the values you list as "second factor done" | `Identity__StepUp__AcrValues` (default `mfa`, comma-separated, case-sensitive) |
| `auth_time` | when the user last signed in, Unix seconds | `Identity__StepUp__MaxAgeSeconds` (default `300`, 1 to 86400) |

A token that lacks either claim, has another `acr`, or whose sign-in is older than the limit gets `401` with a standard
`WWW-Authenticate: Bearer error="insufficient_user_authentication"` challenge. The Web UI answers it by sending the user to the
identity provider once more (asking for the same `acr_values` and `max_age`) and returns to the page; `qca` prints the
`qca auth login --acr-values ... --max-age ...` to run. A caller without the permission still gets `403`, never the challenge.

Things to know:
- **Machine clients are refused** for these operations unless the identity provider is set to stamp `acr` and `auth_time` on their tokens. That is your decision to make in the provider, and a leaked client secret would then pass the check.
- **`Identity:Authority` must equal the token's `iss` exactly**, including any realm path and the host name the provider advertises (Keycloak: `https://host/realms/<realm>`).
- The built-in identity service does not emit these claims, so step-up needs an external provider. Its own admin pages keep their separate password re-confirmation.
- Logs show `Step-up required for <method> <route>: <reason>` at Information; refusals are not audited.

## Enabling TPM-backed secret storage

By default, Qertum protects its Data Protection key ring (which encrypts the CA private key,
stored certificate keys, ACME MAC keys and webhook secrets) and the IdentityService's signing
certificates with locally generated file keys under `/data`. With a TPM 2.0 chip on the host, those keys can be sealed to
the TPM instead, so a copy of `/data` alone no longer decrypts anything.

**Understand the trade-off first.** A TPM-sealed key never leaves the TPM that sealed it. A
backup restored onto other hardware — a replacement server, a new motherboard, a cleared TPM —
cannot decrypt the CA key. Before moving hosts, migrate back to the local file key (see [Moving to other hardware, and losing the TPM](#moving-to-other-hardware-and-losing-the-tpm)).

1. Pass the device through (`--device /dev/tpmrm0`, or `devices:` in compose), and since the
   services run as the unprivileged `app` user, add the device's group so it can open it
   (`--group-add "$(stat -c %g /dev/tpmrm0)"`, or `group_add:` in compose). Then set
   `IdentityService__SecretStorageProvider=LocalTpm`, then re-create the container. On that
   start the IDM re-encrypts `/data/identity/keys/` and records `SecretStorageMigrated` in its
   audit log.
2. From an account with `settings.edit`, go to Settings → Secret Storage, which now reports a
   TPM, and migrate to "Local TPM". This re-encrypts the CA's key ring.
3. Restart the container so every service picks up the new key ring provider.

### Moving to other hardware, and losing the TPM

TPM-backed storage trades portability for protection: the wrapping key is sealed under the TPM's own
storage hierarchy, so it unseals only on that TPM. There is **no export**: Qertum has no way to write
the CA private key out, and a copy of `/data` alone no longer decrypts it. Read this before you turn
the option on, and again before you change the hardware.

**What the key protects.** The Data Protection key ring, which encrypts the CA private key, stored
certificate keys, ACME MAC keys and webhook secrets; and, for the identity provider, its signing and
encryption certificates (`keys/*.pfx` on its own volume). Users, clients and roles in the identity
provider are not encrypted with it.

**When the key is lost.** The TPM cleared (from the firmware setup, or `tpm2_clear`), replaced, or the
board or CPU swapped on a machine with a firmware TPM, changes what the sealed blob can unseal to. A
routine kernel or firmware update does not: no PCR policy is used. Then the services that build the
key ring (API, ACME and queue consumer here; EST too where deployed) stop at startup with a
`tpm2_*` error, for example `'tpm2_load …' exited with code …` (a cleared or different TPM derives a
different primary key, so loading the sealed blob fails), and so does the identity provider. Deleting
`secret-storage/tpm-sealed.blob` does not help: Qertum would seal a new key, and nothing encrypted
under the old one can be read.

**Planned move (the TPM still works): leave TPM storage first.**
1. Take a backup and prove it: `./backup.sh ./backups`, then `./restore-test.sh ./backups`. Keep it, but
   know that it restores only onto this TPM.
2. Migrate the CA's key ring off the TPM: Settings → Secret Storage → *Migrate to* *Local file key* → Migrate (needs
   `settings.edit`), then restart the container so all four hosts pick it up.
3. Move the identity provider's keys: set `IdentityService__SecretStorageProvider=LocalFileKey` and
   re-create the container. It re-encrypts `keys/` at startup and refuses to start, changing nothing,
   if it cannot.
4. Check Settings → Secret Storage shows *Current provider: LocalFileKey*, and that you can still sign
   in and see the CA and its issuers.
5. Take a new backup and run `restore-test.sh` on it. **This** one is portable. Restore it on the new
   hardware as described under *Restoring from a backup*, start the container, check as in step 4.
6. Optional: turn TPM storage on again on the new host (the section above).

What step 2 leaves behind: `secret-storage/tpm-sealed.blob` stays on disk (useless without the old
TPM) and `secret-storage/local.key` now sits beside the data. Until you seal again, anyone holding a
copy of `/data` can decrypt it, so keep the backup archives where only you can read them.

**Unplanned loss (the TPM is gone or cleared).** What Qertum stored under TPM protection cannot be
recovered. The ways forward, best first:
- **Restore an older backup taken before TPM storage was enabled** (the local file key travels with the
  archive). You get the CA as it was then; read *What a restore changes* under *Restoring from a
  backup* for the gap.
- **Offline root: replace only the online issuer.** If the root was created offline (onboarding's
  *Offline root + online intermediate*, or `qca root`), only the online intermediate's key is lost.
  Create a new intermediate signed by the offline root, make it the default, and keep the old one
  retired. Relying parties keep trusting the same root. Certificates the lost intermediate issued stay
  valid until they expire, but Qertum cannot sign a new CRL for it, so the last published CRL simply
  ages out and those certificates can no longer be revoked.
- **Online root, no usable backup: start a new CA.** Onboard a new root, issue replacements and
  distribute the new trust anchor. The old CA cannot be revoked or renewed from Qertum.
- **Identity provider.** Remove `keys/` and `secret-storage.json` from its data directory (and the old
  sealed blob), then start it: it creates new signing and encryption certificates. Everyone is signed
  out; users, clients and roles are untouched.

**Rehearse it before you rely on it.** Do step 2 and step 3 on a spare instance, then restore its new
backup somewhere else. Moving onto the TPM (the section above) was run on one x86_64 TPM 2.0 with the multi-container image on 2026-10-20 (see its README); the steps for leaving the TPM, and the single-container image with a TPM, were checked against the code, not run on TPM hardware.

## Backup & restore

`/data` holds the CA private key, the shared DB, the Data Protection keyring and the
keys that wrap it, and the IDM store — there is no other copy. With TPM-backed storage,
a backup restores only onto the same TPM (see above). `backup.sh` and `restore.sh` (with `.ps1` equivalents for Windows/PowerShell) wrap this in
a single command each; both work against a running container regardless of
whether `/data` is a bind mount or a named volume (they use
`docker run --volumes-from`, not the host path).

An administrator can also export the CA key itself (`qca issuers export-key` or `export-pfx`). That is not
a backup strategy: it is unencrypted key material outside `/data`, and anyone holding it can sign for your CA.
Back up `/data`; export the key only for an offline copy you will store securely, and delete the rest.

```bash
# Take a backup (stops the container briefly for a consistent snapshot, then
# restarts it):
./backup.sh ./backups
# Or on Windows PowerShell:
# .\backup.ps1 .\backups

# Restore onto a freshly created container (docker compose up once first, then):
./restore.sh ./backups/qertum-backup-20260703T120000Z.tar.gz
# Or on Windows PowerShell:
# .\restore.ps1 .\backups\qertum-backup-20260703T120000Z.tar.gz
```

Recommendations:
- Schedule `backup.sh` (e.g. an Unraid User Script or cron job, or Windows Task Scheduler for `backup.ps1`) and copy the
  resulting archives off-box — a backup that lives on the same disk as the
  original doesn't protect against disk failure.
- **Prove the backup, side by side with the running container.** `backup.sh`/`backup.ps1` write a manifest next to every archive (`qertum-backup-<timestamp>.manifest`: a SHA-256, mode, owner and size for each file of `/data`, taken while the container was stopped). `./restore-test.sh ./backups` (or `.\restore-test.ps1 .\backups`) takes the newest archive that has a manifest, extracts it into a scratch Docker volume, recomputes the manifest and compares. It never stops or changes the running container. It then opens the restored copy offline with the image of the running container (or `--image <ref>` / `-Image`): no network, no services started, it decrypts a stored secret with the restored key ring, signs a probe with each online issuer and builds a CRL that lists every revoked certificate. Exit `0` means the archive is byte-for-byte the data that was on `/data` at backup time **and** the restored copy works, and records a *usable* restore on the dashboard (only *verified* if no image is known); a failure of either step is recorded as *failed* on the dashboard until the next restore record (a passing test, or a plain restore) replaces it; `1` means a file differs, is missing or was added (each path is listed), the archive cannot be extracted, or a check failed (named in the output); `2` means it could not test (no Docker, no manifest, nothing found, a backup from another Qertum version than the image, an image older than the check); nothing is recorded then. Schedule it after `backup.sh`, the same way.
  **What "verified" and "usable" mean:** *verified* is only that the archive is a faithful copy. *Usable* adds that the restored files work when read by this Qertum version (database, key ring, CA signing, CRL). A check with nothing to test (no encrypted secret stored, no online issuer, a CA never onboarded) is printed as *not exercised* and *usable* says nothing about it. Neither starts the running stack (identity, API, web, queue, Redis), and *usable* cannot test keys held in a TPM or an external vault. Neither is tamper protection: whoever can change both the archive and its manifest can forge a pass. A backup taken before manifests existed has none and cannot be verified. Symlinks and empty directories are not checked. The `.ps1` scripts need PowerShell 7 (`pwsh`; Windows PowerShell 5.1 is not supported) and were run under pwsh 7.6 on macOS; run them once on your Windows machine before relying on them there.
- The backup briefly stops the container (SQLite + the CA files aren't safe to
  tar while a process is writing them); plan for a few seconds of downtime per
  backup run.
- **What Qertum shows about your backups.** `backup.sh`/`backup.ps1` write `/data/recovery/last-backup.json` after the archive succeeds, and `restore.sh`/`restore.ps1` write `last-restore.json` and leave `/data/recovery` alone. Settings → System → *Backup & recovery* and the dashboard's *Attention required* show the age against limits you set (default 48 hours for a backup, 35 days for a verified restore). This is **what the script reported**, not something Qertum checked: it has not opened the archive or tried a restore, and anything that can write the data volume could forge the files. Nothing reported is shown as *Not reported*, not as a warning, so a deployment that backs up the volume another way is not nagged. A plain restore is recorded as *performed*; only `restore-test.sh` records *verified*, *usable* or *failed*, and a later plain restore overwrites it (it is one file).
- **Check the scripts after editing them:** create a scratch container on a scratch volume (`docker volume create`, `docker create --name scratch -v vol:/data alpine sleep 3600`), run `backup.sh`, change a file and `recovery/marker`, run `restore.sh`, and confirm the database came back, `recovery/marker` kept its live value, and `last-restore.json` says `"kind":"performed"`. Do the same for `restore-test.sh`: it must pass on the fresh backup (`"kind":"usable"`), fail naming each path after you change, delete or add a file in a copy of the archive (`"kind":"failed"`), and fail at `key-ring` for a copy whose `DataProtection-Keys` directory is removed and whose manifest you regenerate with `manifest.sh`.

### Restoring from a backup

Restoring replaces everything on `/data` with the state at the moment the archive was taken. Read
"What a restore changes" before you start: it is a rollback, not a merge.

**Before you start**
- **Same image, same address.** Run the same image tag as the backup came from (`QERTUM_IMAGE_TAG`,
  see below), with the same `QERTUM_HOST` and the same published ports. The OIDC authority, the
  redirect URIs and the ACME directory URL are derived from them at start, so clients that trust the
  old address keep working only if it is unchanged.
- **Same TPM, if you use one.** A backup taken with `LocalTpm` secret storage restores only onto the
  TPM that sealed it, with the device passed through as before. On other hardware the CA key cannot be
  decrypted (see [Enabling TPM-backed secret storage](#enabling-tpm-backed-secret-storage)).
- **Keep a copy of what is there now.** `restore.sh` clears `/data` (except `/data/recovery`) before it
  extracts, and that cannot be undone. If the current volume is still readable, take a backup of it
  first: `./backup.sh ./before-restore`.

**Steps**
1. **Pick the archive and prove it is intact.** `./restore-test.sh ./backups` tests the newest archive
   that has a manifest; `./restore-test.sh ./backups/qertum-backup-<timestamp>.tar.gz` tests the one
   you name. Exit `0` means it matches `/data` as it was at backup time (see above for what that does
   not cover). Do not restore from an archive that fails or has no manifest unless you have no other.
2. **Make sure the container exists.** On a new host, copy the archive and the `docker-compose.yml`,
   then run `docker compose up -d` once. This creates the container and an empty `/data`; the restore
   replaces that. On an existing host the container is already there.
3. **Restore.** `./restore.sh ./backups/qertum-backup-<timestamp>.tar.gz [container-name]`
   (`.\restore.ps1` on Windows). It asks for confirmation, stops the container, clears `/data` except
   `/data/recovery`, extracts the archive, records a *performed* restore, and starts the container
   again if it was running. If the container was stopped when you began, start it yourself
   (`docker start qertum`).
4. **Check that it came back.**
   - Wait for the services (the log lists the web, identity, API and ACME addresses), then sign in
     with an account that existed at backup time.
   - Settings → System shows the CA as initialised, with the issuers you expect.
   - `qca doctor` runs read-only checks against the API.
5. **Record the result.** `./restore-test.sh <the same archive>` marks the restore *usable* on the
   dashboard. A plain restore is only *performed*; nothing has checked that the instance works until
   you have signed in and looked.

**Tamper-evident audit log.** Every audit line carries a hash chain (one chain per service: the API, the
queue consumer, the identity service, ...), so editing, deleting, inserting or swapping an entry breaks it.
Qertum cannot keep a copy off the host for you. To make the chain worth something, create a webhook
subscribed to **`AuditCheckpoint`** pointing at a receiver on **another host** that stores every body (a small
script, a collector, a ticket queue); the event is sent every `AuditLog:Checkpoint:IntervalMinutes` (default
60) and carries the head of each chain. `qca audit checkpoint --output json` prints the same on demand.
To check a log, copy `/data/audit-logs` (and `/data/identity/audit-logs`) somewhere and run
`qca audit verify <dir> --anchor <saved checkpoint>`: exit 0 means every chain is intact and the anchored
entries are in it. What it does **not** catch: anything after the newest checkpoint you hold (cutting the tail
off the log), so a shorter interval narrows that window. A restore from backup rewinds the log, so
checkpoints taken after the backup report `AnchorBeyondLog`; that is correct, those audit entries are gone.
Entries written before this feature existed are not chained and are not checked. A checkpoint covers the identity service's chain only when its audit directory is visible to the queue consumer (the default `/data/identity/audit-logs`, or `AuditLog:Checkpoint:IdentityDirectory`); if the identity service writes to a volume the queue consumer cannot see, its chain is absent from the webhook and is not anchored.

**What a restore changes**
- **Anything after the backup is gone.** Requests, approvals, issued certificates, revocations,
  settings and audit entries made after the archive was taken are not in the restored database. A
  certificate issued after the backup is still valid wherever it was installed, but this CA has no
  record of it and cannot revoke it. A certificate revoked after the backup is *not* revoked again;
  revoke it once more, and look through your webhook receivers and audit copies for what happened in
  the gap.
- **CRL numbers roll back.** Each CRL carries a number taken from a counter in the database, which
  returns to its value at backup time. A CRL published after the restore can carry a lower number than
  one clients already saw, and clients that require increasing numbers may keep the old one. After the
  restore, publish a fresh CRL (`qca ca crl reset-base`, or `POST /v1/crl/reset-base`; needs `settings.edit`) and check the number against what
  your relying parties last fetched. Certificate serial numbers are random, so they are not reused.
- **Caches start empty.** Redis is not persisted, so the CRL and ACME nonces are rebuilt on first use.
- **ACME accounts and EST credentials** are in the database, so clients that registered after the
  backup must register again.

**Rehearsing**
`restore-test.sh` proves the archive is a faithful copy and that the restored files work when opened offline; it does not start the running stack. For a compromised CA key (not a lost server), see [Issuer Compromise Recovery](https://github.com/Qertum/qertum/wiki/Issuer-Compromise-Recovery). A full rehearsal means
restoring onto a spare host with the same `QERTUM_HOST` and ports and signing in. It cannot run beside
the live container on one host, because the advertised ports must match the published ones.

## Caveats

- No EST, by design. This image is the small-deployment SKU (ACME only); EST is part of the
  [multi-container deployment](../multi-container/README.md), which also exposes ACME and EST without
  exposing the API, identity or web UI.
- Single container = no independent scaling and a shared failure domain. Fine for
  a homelab CA; not for multi-tenant production.
- SQLite + one volume avoids the cross-container file-locking pain of a shared
  volume, but still single-writer; the architecture already serializes writes
  through the API + queue consumer.
- Plain HTTP exposes tokens/credentials on the wire. Keep it on a trusted LAN or
  put TLS in front (web, identity and API only; never ACME).

## Two-person approval

Optional and off by default: an administrator switches it on in Settings → Issuance (or `qca approvals switch on`, or `PUT /v1/settings/two-person-approval`). While it is on, downloading someone else's private key, changing issuers, executing a bulk revoke and publishing an issuance policy each need a second administrator's approval, spent as a one-use grant within a time window. **With a single administrator those operations cannot be done until it is switched off again** (switching it off needs no approval). The time limits are `Approvals__GrantWindowMinutes` (default `15`, 1 to 1440), `Approvals__RequestTtlHours` (default `24`, 1 to 168) and `Approvals__RetentionDays` (default `365`, 1 to 3650), set on `the container`.

## Image tags

`docker-compose.yml` reads the registry from `QERTUM_REGISTRY` and the tag from `QERTUM_IMAGE_TAG`
(default `latest`). Pin an exact tag, for example `QERTUM_IMAGE_TAG=alpha-02`, so you decide when to
upgrade and can roll back; for Docker Hub set `QERTUM_REGISTRY=docker.io/qertum`.
