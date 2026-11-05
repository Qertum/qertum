# Release signing keys

Qertum releases are signed with [cosign](https://github.com/sigstore/cosign). Each release's container images (on Docker Hub, Quay and GHCR) carry a signature, and so does its `SHA256SUMS` file (`SHA256SUMS.sigstore.json`, a release asset). `SHA256SUMS` lists the checksums of every other asset: the deploy bundle, the `qca` binaries, the SBOMs and the third-party notices. Signatures are recorded in the public Sigstore transparency log (Rekor).

Releases before 1.0.0-rc6 are not signed.

| Key | File | SHA-256 of the public key (DER) |
|---|---|---|
| Primary | `qertum-release-primary.pub` | `4c701e20c6159396f22c1ed6618ea6ac0aa1eca03682c6a8cd21c844521e3532` |
| Spare | `qertum-release-spare.pub` | `9ab9896c2ce429e446df11e011467361530c85fcd14ca194a1a3ff288108ab7c` |

A release is signed with the primary key. The spare is kept offline and used only if the primary is lost or broken; the release notes say so when that happens. Both are ECDSA P-256 keys generated inside a YubiKey 5 (firmware 5.8), which cannot export them, and every signature needs the key's PIN and a touch.

## Verifying

Install cosign 3.0 or later, then, from a checkout of this repository or with the key files downloaded:

```
cosign verify --key signing/qertum-release-primary.pub qertum/qertum:<tag>
cosign verify --key signing/qertum-release-primary.pub qertum/qertum-services:<tag>
```

For the release files, download `SHA256SUMS`, `SHA256SUMS.sigstore.json` and the files you need from the GitHub release, then:

```
cosign verify-blob --key signing/qertum-release-primary.pub --bundle SHA256SUMS.sigstore.json SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

The first command proves `SHA256SUMS` is the one we signed; the second proves your downloads match it. On macOS use `shasum -a 256 --check --ignore-missing SHA256SUMS`. If a verification fails with the primary key, try the spare key before treating the download as untrusted.

The wiki page [Verify a Release](https://github.com/Qertum/qertum/wiki/Verify-a-Release) walks through the same steps.

## Proof that the keys live in a YubiKey

`qertum-release-<key>.attestation.pem` is the YubiKey's attestation certificate for the signing slot, and `qertum-release-<key>.attestation-ca.pem` is the device's attestation certificate that signed it, issued by Yubico. The attestation certificate holds the same public key as the `.pub` file, the YubiKey's serial number, and its PIN and touch policies (both "always"). To check the chain, add Yubico's attestation root and intermediate certificates from [developers.yubico.com/PKI](https://developers.yubico.com/PKI/):

```
openssl verify -partial_chain -CAfile <yubico-certs.pem> -untrusted qertum-release-primary.attestation-ca.pem qertum-release-primary.attestation.pem
```

## If a key is compromised or lost

We announce it in a GitHub security advisory and the release notes, say which releases the key signed, and publish its replacement here. A signature by a withdrawn key on a release made after the announcement is not genuine.
