using System.Net;
using Org.BouncyCastle.X509;
using Qertum.Services;

namespace Qertum.Cli.Doctor.Checks;

/// <summary>
/// The trust bundle (anonymous) holds roots that are self-signed and in date, and this machine's trusted-root
/// stores are looked up for each. With the issuer list from the issuers check, each Active or Retired issuer's
/// chain (also anonymous) is verified to a bundle root. No request carries the token.
/// </summary>
internal sealed class TrustCheck : IDoctorCheck
{
    public string Id => "trust";

    public async Task<DoctorResult> RunAsync(DoctorContext context, CancellationToken ct)
    {
        if (context.ApiUrl is null || !context.Shared.ApiReachable)
            return DoctorResult.Skip(Id, "needs the api check to pass");

        var bundleUri = DoctorUrls.Combine(context.ApiUrl, "/v1/issuers/trust-bundle?format=pem");
        var response = await DoctorHttp.GetAsync(context, bundleUri, bearerToken: null, 1 << 20, ct);
        if (!response.Ok)
        {
            var (summary, hint) = DoctorHttp.Explain(response, bundleUri, context.Timeout);
            return DoctorResult.Of(Id, DoctorStatus.Fail, summary, hint: hint);
        }

        if (response.Status == HttpStatusCode.ServiceUnavailable)
            return DoctorResult.Of(Id, DoctorStatus.Fail, "the server has no trust anchor configured yet",
                hint: "finish CA onboarding, then run doctor again");
        if (response.Status != HttpStatusCode.OK)
            return DoctorResult.Of(Id, DoctorStatus.Fail, $"the trust bundle request answered {(int)response.Status!.Value}");

        var roots = DoctorCerts.ParseBundle(response.Body);
        if (roots.Count == 0)
            return DoctorResult.Of(Id, DoctorStatus.Fail, "the trust bundle holds no certificate",
                hint: "is --api-url the API (not a web page that answers 200 to everything)?");

        var findings = new List<(DoctorStatus Status, string Text)>();
        var verified = new List<string>();
        var notVerified = new List<string> { "browser, JVM and Firefox trust stores, which have their own roots", "revocation of the chain" };
        var now = context.NowUtc;
        var cannotTell = false;
        var goodRoots = 0;

        foreach (var root in roots)
        {
            var name = DoctorCerts.Name(root);
            if (!DoctorCerts.IsSelfSigned(root))
            {
                findings.Add((DoctorStatus.Fail, $"'{name}' in the trust bundle is not self-signed, so it is not a root"));
                continue;
            }

            if (now > root.NotAfter)
            {
                findings.Add((DoctorStatus.Fail, $"root '{name}' expired on {root.NotAfter:yyyy-MM-dd}"));
                continue;
            }

            if (now < root.NotBefore)
            {
                findings.Add((DoctorStatus.Fail, $"root '{name}' is not valid until {root.NotBefore:yyyy-MM-dd}"));
                continue;
            }

            goodRoots++;
            var fingerprint = DoctorCerts.Sha256(root);
            switch (context.RootStore.Lookup(fingerprint))
            {
                case RootStoreAnswer.Installed:
                    verified.Add($"root '{name}' is installed in this machine's trusted-root store");
                    break;
                case RootStoreAnswer.NotInstalled:
                    findings.Add((DoctorStatus.Warn, $"root '{name}' (sha256 {fingerprint[..16]}…) is not installed in this machine's trust store"));
                    break;
                default:
                    cannotTell = true;
                    break;
            }
        }

        if (goodRoots > 0)
            verified.Insert(0, $"{goodRoots} root(s): self-signature and validity dates verified");
        if (cannotTell)
            notVerified.Add("whether this machine's trust store holds the root: cannot tell on this platform");
        notVerified.Add("presence in the store only, not that the root is trusted for TLS");

        var issuerCertificates = new List<X509Certificate>();
        if (context.Shared.Issuers is { } issuers)
        {
            var checkedChains = 0;
            foreach (var issuer in issuers.Where(i => i.Status is IssuerStatus.Active or IssuerStatus.Retired))
            {
                var chainUri = DoctorUrls.Combine(context.ApiUrl, $"/v1/issuers/{(Guid)issuer.Id}/chain?format=pem");
                var chainResponse = await DoctorHttp.GetAsync(context, chainUri, bearerToken: null, 1 << 20, ct);
                if (!chainResponse.Ok || chainResponse.Status != HttpStatusCode.OK)
                {
                    findings.Add((DoctorStatus.Fail, $"issuer '{issuer.Name}': its chain could not be fetched"));
                    continue;
                }

                var problem = VerifyChain(DoctorCerts.ParseBundle(chainResponse.Body), roots, now, issuerCertificates);
                if (problem is null) checkedChains++;
                else findings.Add((DoctorStatus.Fail, $"issuer '{issuer.Name}': {problem}"));
            }

            if (checkedChains > 0)
                verified.Add($"{checkedChains} issuer chain(s) verify to a root in the bundle, signatures and dates");
        }
        else
        {
            notVerified.Add("issuer chains (the issuer list needs a login)");
        }

        context.Shared.Roots = roots;
        context.Shared.IssuerCertificates = issuerCertificates;

        var worst = findings.Count == 0 ? DoctorStatus.Pass : findings.Max(f => f.Status) == DoctorStatus.Fail ? DoctorStatus.Fail : DoctorStatus.Warn;
        return DoctorResult.Of(Id, worst,
            worst switch
            {
                DoctorStatus.Fail => "the trust anchors have problems",
                DoctorStatus.Warn => "the root is not installed on this machine",
                _ => "the roots verify and this machine's trust store is in order"
            },
            verified: verified, notVerified: notVerified, findings: findings.Select(f => f.Text),
            hint: worst == DoctorStatus.Pass ? null : "download the root with 'qca issuers trust-bundle --file trust.pem' and add it to your operating system's trust store");
    }

    /// <summary>Null when the chain (leaf first) verifies link by link to a bundle root, with every date valid.</summary>
    private static string? VerifyChain(IReadOnlyList<X509Certificate> chain, IReadOnlyList<X509Certificate> roots, DateTime now, List<X509Certificate> collected)
    {
        if (chain.Count == 0)
            return "its chain holds no certificate";

        for (var i = 0; i < chain.Count; i++)
        {
            if (now > chain[i].NotAfter || now < chain[i].NotBefore)
                return $"'{DoctorCerts.Name(chain[i])}' is outside its validity dates";
            if (i + 1 < chain.Count && !DoctorCerts.VerifiesWith(chain[i], chain[i + 1]))
                return $"'{DoctorCerts.Name(chain[i])}' is not signed by '{DoctorCerts.Name(chain[i + 1])}'";
        }

        var top = chain[^1];
        if (!roots.Any(r => DoctorCerts.Sha256(r) == DoctorCerts.Sha256(top)) && !roots.Any(r => DoctorCerts.VerifiesWith(top, r)))
            return $"its chain ends at '{DoctorCerts.Name(top)}', which is not a root in the trust bundle";

        collected.AddRange(chain);
        return null;
    }
}
