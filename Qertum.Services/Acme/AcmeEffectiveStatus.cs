namespace Qertum.Services.Acme;

/// <summary>
/// Status as reported, derived from expiry at read time. Shared by the ACME endpoints and the orders
/// API so the two cannot disagree; the stored row keeps its own value.
/// </summary>
public static class AcmeEffectiveStatus
{
    public static string Authorization(AcmeAuthorization auth, DateTime now)
        => auth.Status is "invalid" or "revoked" or "deactivated" || auth.ExpiresAtUtc > now
            ? auth.Status
            : "expired";

    public static string Order(AcmeOrder order, DateTime now)
        => order.Status is "valid" or "invalid" || order.ExpiresAtUtc > now
            ? order.Status
            : "invalid";
}
