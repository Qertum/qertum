namespace Qertum.Services;

/// <summary>RFC 6960 §2.2 certificate status values.</summary>
public enum OcspCertificateState
{
    /// <summary>The certificate is not revoked. Note this says nothing about whether it ever existed.</summary>
    Good,

    /// <summary>The certificate has been revoked.</summary>
    Revoked,

    /// <summary>The responder cannot say anything about this serial — a different CA, or a serial it never issued.</summary>
    Unknown
}

/// <summary>
/// Revocation status of one serial, as the responder should report it.
/// </summary>
/// <param name="State">What to report for this serial.</param>
/// <param name="RevokedAtUtc">When it was revoked; required when <paramref name="State"/> is <see cref="OcspCertificateState.Revoked"/>.</param>
/// <param name="RevocationReason">The stored free-text reason, mapped onto an RFC 5280 reason code by the responder.</param>
public sealed record OcspCertificateStatus(
    OcspCertificateState State,
    DateTime? RevokedAtUtc = null,
    string? RevocationReason = null)
{
    /// <summary>Status for a serial this CA has issued and not revoked.</summary>
    public static readonly OcspCertificateStatus Good = new(OcspCertificateState.Good);

    /// <summary>Status for a serial this responder knows nothing about.</summary>
    public static readonly OcspCertificateStatus Unknown = new(OcspCertificateState.Unknown);
}
