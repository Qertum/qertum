# Security policy

Qertum is a certificate authority, so a vulnerability in it can put an organisation's trust at risk. Please report one privately and give us a chance to fix it before it is public.

## Reporting a vulnerability

Email **security@qertum.com**. Please do not open a public issue or pull request for a vulnerability.

Include what you can of:

- the affected version or image tag, and how it is deployed (single container, multi container, or from source);
- what an attacker needs (network access, a valid account, a particular role) and what they gain;
- steps or a proof of concept that reproduce it;
- whether the issue is already public or has a deadline attached.

We aim to acknowledge a report within five working days, tell you whether we consider it a vulnerability, and keep you informed until a fix is released. This is a goal, not a commitment: see below. We credit reporters in the release notes unless you prefer not to be named.

## How we handle a report

Qertum is free, open-source software, provided as is under the [MIT licence](LICENSE), without warranty. No support plan is sold for it, so there is no guaranteed response time and no guaranteed fix. The maintainers still treat security reports first, on a best-effort basis:

1. we assess the report and tell you what we found;
2. we fix a confirmed vulnerability in a new release as soon as we can, and the release notes name the affected versions, the fix and any workaround;
3. we agree the publication date with you, and announce an actively exploited vulnerability through a GitHub security advisory without waiting for the next planned release.

Releases from 1.0.0-rc6 are signed; the public keys and how to check a download are in [signing/](signing/README.md).

When the vulnerability is in a component Qertum ships (the base image, Valkey, a .NET library), we report it to that component's maintainer as well.

**EU Cyber Resilience Act.** CALM Oy, which maintains Qertum, does not monetise it: there is no paid licence, support plan or hosted service. Qertum is therefore not made available in the course of a commercial activity, and the CRA's manufacturer obligations do not apply to it at present. We follow its good practice where we can: this disclosure policy, a CycloneDX SBOM for every image, and prompt advisories. If a commercial offering (a hosted service or paid support) is ever introduced, this section will say which obligations then apply.

## Supported versions

Qertum is at the release-candidate stage. Security fixes, when we make them, go into the **latest release** only, published as a new image tag. Pin an exact tag, read the release notes when you upgrade, and take a backup first (see the Upgrading page in the wiki). From 1.0.0 the [support and compatibility policy](SUPPORT.md) says which releases we aim to fix. Neither is a guarantee.

## What counts

In scope: flaws in the services, images and command-line client in this repository, for example authentication or authorisation bypass, exposure of private keys or issuer keys, forged or mis-issued certificates, request forgery against the ACME or EST endpoints, tampering with or evading the audit trail, and injection.

Documented behaviour is not a vulnerability by itself. In particular, an administrator can export the CA key (it is audited, can require a second administrator and step-up, and the interface says it is not a safe way to manage a CA key), and revoked access tokens stay valid until they expire, which is why token lifetimes should be short.

Reports that need an already-compromised host or administrator account, denial of service by sending unreasonable volumes of traffic, and findings in third-party software we only deploy (the base image, Valkey, your identity provider) belong with their maintainers, though we want to hear about a configuration of ours that makes them exploitable.

Operators: what EU rules ask of you when you run Qertum (GDPR, NIS2, eIDAS) is on the [Compliance](https://github.com/Qertum/qertum/wiki/Compliance) wiki page.
