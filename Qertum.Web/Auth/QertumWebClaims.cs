namespace Qertum.Web.Auth;

/// <summary>Claim types the Web cookie carries beyond the OIDC set.</summary>
public static class QertumWebClaims
{
    /// <summary>
    /// One claim per permission the API reports as granted. Refreshed with the roles, so a revoked
    /// grant stops opening a page at the next revalidation rather than at cookie expiry.
    /// </summary>
    public const string Permission = "qertum:permission";
}
