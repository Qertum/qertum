using Qertum.Services;

namespace Qertum.Web.Components.Layout;

/// <summary>Where the revoked-CA banner's "Renew it" goes: each kind of CA renews in its own place.</summary>
public static class CaRevokedBanner
{
    /// <summary>An intermediate renews from the Issuers page, opened with every issuer listed (a revoked one is not "valid"); a root from its certificate page, reached from the revoked list.</summary>
    public static string RenewHref(IssuerKind? revokedKind) => revokedKind == IssuerKind.Intermediate ? "/issuers?valid=0" : "/revoked";
}
