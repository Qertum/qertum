# Security policy

Qertum is a certificate authority, so a vulnerability in it can put an organisation's trust at risk. Please report one privately and give us a chance to fix it before it is public.

## Reporting a vulnerability

Email **security@qertum.com**. Please do not open a public issue or pull request for a vulnerability.

Include what you can of:

- the affected version or image tag, and how it is deployed (single container, multi container, or from source);
- what an attacker needs (network access, a valid account, a particular role) and what they gain;
- steps or a proof of concept that reproduce it;
- whether the issue is already public or has a deadline attached.

We aim to acknowledge a report within five working days, tell you whether we consider it a vulnerability, and keep you informed until a fix is released. We credit reporters in the release notes unless you prefer not to be named.

## Supported versions

Qertum is at the release-candidate stage. Only the **latest release** receives security fixes, and fixes are published as a new image tag. Pin an exact tag, read the release notes when you upgrade, and take a backup first (see the Upgrading page in the wiki). From 1.0.0 the [support and compatibility policy](SUPPORT.md) applies: the latest minor release receives fixes, and the previous minor release for 90 days after a new one.

## What counts

In scope: flaws in the services, images and command-line client in this repository, for example authentication or authorisation bypass, exposure of private keys or issuer keys, forged or mis-issued certificates, request forgery against the ACME or EST endpoints, tampering with or evading the audit trail, and injection.

Documented behaviour is not a vulnerability by itself. In particular, an administrator can export the CA key (it is audited, can require a second administrator and step-up, and the interface says it is not a safe way to manage a CA key), and revoked access tokens stay valid until they expire, which is why token lifetimes should be short.

Reports that need an already-compromised host or administrator account, denial of service by sending unreasonable volumes of traffic, and findings in third-party software we only deploy (the base image, Redis, your identity provider) belong with their maintainers, though we want to hear about a configuration of ours that makes them exploitable.
