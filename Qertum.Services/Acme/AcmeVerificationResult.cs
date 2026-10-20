namespace Qertum.Services.Acme;

/// <summary>Why a challenge attempt failed. Stored as a diagnostic event's category.</summary>
public enum AcmeChallengeFailure
{
    None,
    AllowlistDenied,
    ConnectionFailed,
    Timeout,
    HttpStatus,
    KeyAuthorizationMismatch,
    DnsNoTxtRecord,
    DnsLookupFailed
}

/// <summary>
/// One verification attempt. <see cref="ErrorDetail"/> is served back to the ACME client in the
/// challenge's error and recorded as a diagnostic, so it never carries the token.
/// </summary>
public readonly record struct AcmeVerificationResult(bool Success, string? ErrorDetail, AcmeChallengeFailure Failure)
{
    public static AcmeVerificationResult Valid { get; } = new(true, null, AcmeChallengeFailure.None);

    public static AcmeVerificationResult Failed(AcmeChallengeFailure failure, string detail) => new(false, detail, failure);

    /// <summary>The (success, detail) pair, which is what most callers read.</summary>
    public void Deconstruct(out bool success, out string? errorDetail)
    {
        success = Success;
        errorDetail = ErrorDetail;
    }
}
