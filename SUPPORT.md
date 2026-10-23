# Support and compatibility policy

This page says what a Qertum version number promises, which releases receive security fixes, and where to get help. It takes effect with **1.0.0**. Releases before that (the `alpha-NN` tags and `1.0.0-rcN`) carry no compatibility promise: read the release notes of each one before you upgrade.

## Versioning

Releases follow [Semantic Versioning 2.0](https://semver.org/): `MAJOR.MINOR.PATCH`.

- A **patch** release fixes bugs and security problems and changes nothing described below as covered.
- A **minor** release adds features. It does not remove or change the behaviour of anything covered, except as noted under "Security fixes and standards".
- A **major** release may break covered interfaces. The release notes list every break and how to move.

The image tag is the version, for example `qertum/qertum:1.2.3`. Pin an exact tag. `latest` is for trying Qertum out, not for a CA you depend on.

## What a version number covers

These are the interfaces you build on. They do not change incompatibly within a major version:

- **The REST API** under `/v1`: routes, methods, request and response fields, status codes, the problem-details error shape, and the permission each route needs. Adding a route, an optional request field or a response field is not a break, so ignore fields you do not know.
- **The `qca` command line**: command and option names, exit codes, and the shape of `--output json`. The table output is for people and may change.
- **Configuration**: the keys shipped in the services' `appsettings.json` and listed in the [Configuration Reference](https://github.com/Qertum/qertum/wiki/Configuration-Reference), their meaning and their defaults, as environment variables or in a file.
- **Webhooks**: the event names, payload fields and the delivery rules.
- **The audit log file format** and the tamper-evidence chain, so existing logs stay verifiable with newer releases.
- **Metrics**: the OpenTelemetry instrument names and tags documented for alerting.
- **ACME and EST**: the protocols as specified in RFC 8555 and RFC 7030, within the features each page of the wiki says are supported.
- **Deployment files**: the compose files and scripts in `deploy/` of a release match the images of that release.

## What it does not cover

- **The web interface**: layout, wording and navigation can change in any release.
- **The database schema** and the files on the data volume. They belong to the services. Do not read or write them from outside, and do not depend on their layout.
- **Log text** and the console format.
- **Internal service-to-service calls** between the containers of one release. Run all of them from the same tag.
- **Development-only features**: the OpenAPI document and its viewer, and the health endpoints that are off outside Development.
- **The .NET libraries in this repository** (`Qertum.*`). They are not published as packages.

## Deprecation

A covered interface is marked deprecated in the release notes of a minor release, with its replacement, before a major release removes it. A configuration key that is renamed in a minor release keeps working under its old name until the next major release.

## Security fixes and standards

Two things can force a change that this policy would otherwise forbid, and the release notes say so plainly when it happens:

- **A security fix** that cannot keep the old behaviour. For example, a default that is unsafe has to change.
- **Post-quantum algorithms still defined by drafts**, such as the composite signature schemes. If the standard changes an identifier or encoding, Qertum follows it in a minor release, and certificates already issued stay valid under the old form until they expire.

## Upgrading and rolling back

- **Upgrade** from any earlier release of the same major version to a later one directly; you do not have to step through every minor release. Moving to a new major version is supported from the last minor release of the previous major.
- The API service **migrates the database when it starts**. Take a backup and prove it first ([Backup and Restore](https://github.com/Qertum/qertum/wiki/Backup-and-Restore)), then follow [Upgrading](https://github.com/Qertum/qertum/wiki/Upgrading).
- **Downgrading is not supported.** Your rollback is the backup taken before the upgrade, restored with the previous image. An older image is not tested against a database a newer release has migrated.

## Security fixes

Security fixes go to:

- the **latest minor release** of the current major version, and
- the **previous minor release** for 90 days after a new minor release is published.

A fix is published as a new patch release and an image with a new tag. We do not move or replace a tag that was published. To report a vulnerability, follow [SECURITY.md](SECURITY.md).

When a base image or a library we ship has a known vulnerability that affects Qertum, we rebuild and publish a patch release; the release notes name it.

## Supported platforms

- **Images**: `linux/amd64` and `linux/arm64`, on Docker Hub, Quay and GHCR, identical on all three. They need a running Docker or compatible container runtime.
- **Identity providers**: any OpenID Connect provider that meets the documented token contract. Only the providers marked as tested in [Identity Providers](https://github.com/Qertum/qertum/wiki/Identity-Providers) have been run against a real instance; the others follow the contract but are not verified by us.
- **Building from source** needs the .NET SDK version in `global.json` and Docker.

## Getting help

- **Questions and bugs**: open an issue on the GitHub repository. Include the image tag, the deployment shape (single container, multi container or source), and the output of `qca doctor` if you can.
- **Vulnerabilities**: email **security@qertum.com**, not a public issue.
- Help is given on a best-effort basis by the maintainers. There is no service-level agreement and no commercial support.
