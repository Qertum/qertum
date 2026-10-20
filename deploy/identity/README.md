# Qertum Identity Provider — standalone deployment

One container, one process, one volume. The provider shares no code and no database with
the Qertum CA application; they are connected only by an issuer URL.

## First run

This image is not published to a registry yet: `docker compose` builds it from a **checkout of the
repository** at the release tag (the build context is the repository root), so run the commands below
from that checkout. The release's deploy bundle carries this folder for reference only.

1. Set `IdentityService__Authority` in `docker-compose.yml` to the absolute URL browsers
   and CLIs reach this container at. Startup fails if it is unset outside Development.
2. `docker compose -f deploy/identity/docker-compose.yml up -d`
3. On an empty volume the provider seeds `users.json` with an `admin` user. Set
   `IdentityService__SeedAdminPassword` to choose that password; leave it unset and the
   account is seeded with the well-known value `password`.
4. Log in at `{Authority}/login`. If the well-known password was used, the provider forces a
   password change before the account can be used for anything else: no token is issued for
   any grant, and the signed-in session can only reach the change-password page and sign-out
   until the password is changed.
5. **Replace the seeded redirect URIs.** On an empty volume the provider also seeds
   `/data/clients.json` with localhost development placeholders
   (`https://localhost:7077/signin-oidc`, `http://localhost:5137/signin-oidc` and their
   `signout-callback-oidc` counterparts). Edit `/data/clients.json`, replace those with
   your application's real URLs, and restart the container — otherwise every login ends
   in an `invalid_redirect_uri` error. See [Adding a client](#adding-a-client).
6. Point each consuming application at this provider by setting its `Identity__Authority`
   to the same value as `IdentityService__Authority`.

## Behind a reverse proxy

`IdentityService__Authority` pins **only** the `iss` claim and the discovery document's
`issuer` field. OpenIddict builds every advertised endpoint URL — `authorization_endpoint`,
`token_endpoint`, `device_authorization_endpoint`, `userinfo_endpoint`, `jwks_uri`, the
device-flow `verification_uri`, and the `/login` challenge redirect — from the **incoming
request's** scheme and host. A TLS-terminating proxy therefore must forward both, or
discovery will advertise `http://` URLs under an `https://` issuer and consumers with
`Identity:RequireHttpsMetadata=true` will fail to fetch JWKS.

Requirements on the proxy:

- Send `X-Forwarded-Proto: https`. The image sets `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true`,
  which makes ASP.NET Core apply `X-Forwarded-For` and `X-Forwarded-Proto` to the request.
- Preserve the original `Host` header (nginx: `proxy_set_header Host $host`; Caddy and
  Traefik do this by default). That switch does **not** consume `X-Forwarded-Host`, so the
  host comes from `Host` alone.
- Set `IdentityService__DisableTransportSecurity=true` so OpenIddict accepts the plain-HTTP
  hop between the proxy and the container.

## Configuration

| Key | Required | Default | Purpose |
|---|---|---|---|
| `IdentityService__Authority` | Yes (outside Development) | — | Absolute issuer URL (`http`/`https` only). Written to `iss` and the discovery document's `issuer`. Endpoint URLs are still request-derived — see [Behind a reverse proxy](#behind-a-reverse-proxy). |
| `IdentityService__DataPath` | No | `/data` in the image (falls back to `AppContext.BaseDirectory` if unset outside the image) | Directory holding `users.json`, `clients.json`, `roles.json`, `identity.db`, `keys/`, `secret-storage/` and `audit-logs/`. |
| `IdentityService__SecretStorageProvider` | No | unset | `LocalFileKey` or `LocalTpm`: what protects the certificates in `keys/`. Unset keeps what the volume records (a new volume: `LocalFileKey`). A changed value re-encrypts `keys/` at the next start and logs `SecretStorageMigrated`; if that fails, startup fails and nothing changes. `LocalTpm` needs `--device /dev/tpmrm0`. |
| `IdentityService__CertificateLifetimeDays` | No | `1825` | Validity of newly created signing/encryption certificates. See [Key rotation](#key-rotation). |
| `IdentityService__CertificateRenewBeforeDays` | No | `90` | How long before expiry a replacement is created; also the overlap window. |
| `IdentityService__AuditLog__Path` | No | `{DataPath}/audit-logs/identity-audit-.clef` | Audit log of user and role administration, shown at `/Admin/Audit`. |
| `IdentityService__DisableTransportSecurity` | No | `false` | Opts out of OpenIddict's HTTPS requirement. Set `true` behind a TLS-terminating proxy — and forward scheme/host, see above. |
| `ASPNETCORE_FORWARDEDHEADERS_ENABLED` | No | `true` (set in the image) | Applies `X-Forwarded-For` / `X-Forwarded-Proto` from the proxy. |
| `IdentityService__EnableServiceDiscoveryRedirectUris` | No | Development only | Adds redirect URIs read from `Services__webfrontend__*` on top of `clients.json`. Nothing injects those variables in this deployment, so keep it off here. |
| `IdentityService__ApiClientSecret` | No | generated | Overrides the seeded `qertum-api` client secret. |
| `IdentityService__SeedAdminPassword` | No | `password` | Password for the `admin` user seeded on an empty volume. Read only when `users.json` is absent — changing it later has no effect. When unset, the account is seeded with `password` and flagged: the first login must change it before the account can obtain any token or reach any other page of the provider. |
| `ConnectionStrings__Identity` | No | `{DataPath}/identity.db` | OpenIddict's EF Core store. |

## Adding a client

Edit `clients.json` on the volume and restart. `ClientSeedHostedService` performs a
create-or-update for every entry on each start, so registering a new application is a
file edit plus a restart — no admin UI, by design. Users and roles do have one: the `/Admin`
pages, for accounts holding `admin`, after re-entering their password.

Removing or renaming an entry does not unregister it: the old client stays in `identity.db`
and can still obtain tokens. Delete it there too.

## Key rotation

The provider's own signing and encryption certificates live in `keys/` and are rotated
automatically. Each is issued for `IdentityService__CertificateLifetimeDays` (default 1825,
five years); once the newest is within `IdentityService__CertificateRenewBeforeDays`
(default 90) of expiry, the next start creates a replacement alongside it.

Rotation is additive. Every still-valid certificate stays published in the JWKS document, so
tokens signed with the retiring key keep validating for the rest of the overlap window and
nobody is signed out. Expired files are left on disk, unused — delete them whenever you like.

Set `CertificateRenewBeforeDays` longer than your longest refresh-token lifetime, otherwise a
token issued just before a rotation can outlive the key that signed it.

Rotation is checked at start-up only, so a container that runs longer than the renewal window
without restarting will not rotate — restart it at least once inside that window. The 90-day
default is far longer than any normal update cadence.

## Runs without root

The container starts as root only long enough to make the data volume writable for the
unprivileged `app` user (UID 1654, from the .NET base image), then runs the provider as that user.
A volume written by an older image that ran as root is re-owned once, on the first start; the log
says so. With `LocalTpm`, pass the device's group too (`--group-add "$(stat -c %g /dev/tpmrm0)"`, or
`group_add:` in compose), because the provider can no longer open the device as root.

## Backup

Back up the whole volume. Losing `keys/` invalidates every issued token and logs everyone
out; so does losing `secret-storage/`, because the files in `keys/` are encrypted under the key
it holds. Losing `users.json` loses all accounts, and losing `roles.json` loses the role
catalog.

With `LocalTpm`, the key in `secret-storage/` is sealed to this host's TPM. Restored onto other
hardware, the provider fails at startup because the key cannot be unsealed. Switch back to
`LocalFileKey` before moving hosts. If it is too late, delete `secret-storage/`,
`secret-storage.json` and `keys/` from the volume and unset `IdentityService__SecretStorageProvider`;
the next start mints new certificates and everyone signs in again.
