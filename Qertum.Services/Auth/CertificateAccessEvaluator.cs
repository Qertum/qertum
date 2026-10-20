using System.Security.Claims;

namespace Qertum.Services.Auth;

/// <summary>
/// Decides whether a principal may retrieve the private key of a certificate request.
/// </summary>
public interface ICertificateAccessEvaluator
{
    /// <summary>
    /// True when the principal owns the request, or holds the administrator role.
    /// <c>certificates.manage</c> deliberately does not grant key access: approving and revoking
    /// certificates is a separate concern from reading their key material.
    /// </summary>
    bool CanAccessPrivateKey(ClaimsPrincipal principal, CertificateRequest request);

    /// <summary>
    /// True when the caller may edit the metadata of <paramref name="request"/>: it holds
    /// <c>certificates.manage</c> (resolved by the caller of this method, because the permission policies
    /// succeed only with the HttpContext as resource), or owns the request, or is an administrator.
    /// Same owner rule as key access, so a legacy row without a subject is editable only with manage or admin.
    /// </summary>
    bool CanEditMetadata(ClaimsPrincipal principal, CertificateRequest request, bool canManage);
}

public sealed class CertificateAccessEvaluator(IIdentityClaimsMapper claimsMapper) : ICertificateAccessEvaluator
{
    public bool CanAccessPrivateKey(ClaimsPrincipal principal, CertificateRequest request)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(request);

        if (claimsMapper.IsAdmin(principal))
            return true;

        // Legacy rows without an immutable subject are available only to administrators.
        if (string.IsNullOrWhiteSpace(request.RequestedBySubject))
            return false;

        var subject = claimsMapper.GetSubject(principal);
        return !string.IsNullOrWhiteSpace(subject)
            && string.Equals(subject, request.RequestedBySubject, StringComparison.Ordinal);
    }

    public bool CanEditMetadata(ClaimsPrincipal principal, CertificateRequest request, bool canManage) =>
        canManage || CanAccessPrivateKey(principal, request);
}
