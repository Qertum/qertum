namespace Qertum.Services.Lifecycle;

/// <summary>Diagnostic event action names.</summary>
public static class DiagnosticActions
{
    public const string OrderCreated = "OrderCreated";
    public const string NewOrderRefused = "NewOrderRefused";
    public const string ChallengeTriggered = "ChallengeTriggered";
    public const string ChallengeRefused = "ChallengeRefused";
    public const string ChallengeAttemptFailed = "ChallengeAttemptFailed";
    public const string ChallengeValid = "ChallengeValid";
    public const string AuthorizationValid = "AuthorizationValid";
    public const string AuthorizationInvalid = "AuthorizationInvalid";
    public const string OrderReady = "OrderReady";
    public const string Finalized = "Finalized";
    public const string FinalizeRefused = "FinalizeRefused";
    public const string AuthRefused = "AuthRefused";
    public const string EnrollmentRefused = "EnrollmentRefused";
    public const string Enrolled = "Enrolled";
    public const string ReenrollRefused = "ReenrollRefused";
    public const string JobQueued = "JobQueued";
    public const string JobClaimed = "JobClaimed";
    public const string JobCompleted = "JobCompleted";
    public const string JobRetryScheduled = "JobRetryScheduled";
    public const string JobFailed = "JobFailed";
    public const string JobRecovered = "JobRecovered";
    public const string PqcObserved = PqcEventActions.Observed;
    public const string PqcWarned = PqcEventActions.Warned;
    public const string PqcExceptionApplied = PqcEventActions.ExceptionApplied;

}

/// <summary>
/// Diagnostic categories. The verifier's <c>AcmeChallengeFailure</c> names are categories too; every
/// constant here must have a hint in <see cref="DiagnosticHints"/> (<c>DiagnosticHintsTests</c>).
/// </summary>
public static class DiagnosticCategories
{
    public const string AllowlistDenied = "AllowlistDenied";
    public const string ConnectionFailed = "ConnectionFailed";
    public const string Timeout = "Timeout";
    public const string HttpStatus = "HttpStatus";
    public const string KeyAuthorizationMismatch = "KeyAuthorizationMismatch";
    public const string DnsNoTxtRecord = "DnsNoTxtRecord";
    public const string DnsLookupFailed = "DnsLookupFailed";

    public const string NoIdentifiers = "NoIdentifiers";
    public const string TooManyIdentifiers = "TooManyIdentifiers";
    public const string UnsupportedIdentifierType = "UnsupportedIdentifierType";
    public const string InvalidIdentifier = "InvalidIdentifier";
    public const string WildcardNeedsDns01 = "WildcardNeedsDns01";
    public const string OutsidePolicy = "OutsidePolicy";
    public const string Expired = "Expired";
    public const string OrderNotReady = "OrderNotReady";

    public const string UnparseableCsr = "UnparseableCsr";
    public const string KeyRefused = "KeyRefused";
    public const string PolicyRejected = "PolicyRejected";
    public const string CaNotReady = "CaNotReady";
    public const string DuplicateCommonName = "DuplicateCommonName";

    public const string Disabled = "Disabled";
    public const string WrongSecret = "WrongPassword"; // the stored category name; the value must not change
    public const string Revoked = "Revoked";
    public const string IdentityMismatch = "IdentityMismatch";
    public const string CompositeReenrollUnsupported = "CompositeReenrollUnsupported";

    public const string PqcStage = "PqcStage";
}

/// <summary>Fixed plain-language next steps, keyed by category. Never built from an event's detail.</summary>
public static class DiagnosticHints
{
    private static readonly Dictionary<string, string> Hints = new(StringComparer.Ordinal)
    {
        [DiagnosticCategories.AllowlistDenied] = "Add the address's network to Settings → ACME → challenge networks.",
        [DiagnosticCategories.ConnectionFailed] = "Check that the domain's HTTP server is reachable from the CA on port 80.",
        [DiagnosticCategories.Timeout] = "Check that the domain's HTTP server answers from the CA's network; a firewall may be dropping the connection.",
        [DiagnosticCategories.HttpStatus] = "Serve the token at /.well-known/acme-challenge/<token> with status 200 and no redirect.",
        [DiagnosticCategories.KeyAuthorizationMismatch] = "The client served or published a stale or different value; rerun the ACME client.",
        [DiagnosticCategories.DnsNoTxtRecord] = "Publish the TXT record at _acme-challenge.<name>; a cached negative answer can hide it until its TTL expires.",
        [DiagnosticCategories.DnsLookupFailed] = "Check Acme:Dns01:Resolvers and that the name resolves from the CA.",
        [DiagnosticCategories.NoIdentifiers] = "The client sent an order with no names.",
        [DiagnosticCategories.TooManyIdentifiers] = "Split the order; one order may name at most 100 identifiers.",
        [DiagnosticCategories.UnsupportedIdentifierType] = "Only dns identifiers are supported; IP identifiers are not.",
        [DiagnosticCategories.InvalidIdentifier] = "Use a plain DNS name; IP literals and malformed names are refused.",
        [DiagnosticCategories.WildcardNeedsDns01] = "Wildcard names need dns-01; enable it under Acme:Dns01:Enabled or order the names individually.",
        [DiagnosticCategories.OutsidePolicy] = "The ACME template's issuance policy does not allow this name; change the name or the policy.",
        [DiagnosticCategories.Expired] = "The order or authorization expired; start a new order.",
        [DiagnosticCategories.OrderNotReady] = "Finalize only after every authorization is valid; the client finalized too early.",
        [DiagnosticCategories.UnparseableCsr] = "The CSR could not be parsed; check the client sends a base64 PKCS#10 request.",
        [DiagnosticCategories.KeyRefused] = "The CSR's key algorithm is unsupported or refused by the template's PQC enforcement stage.",
        [DiagnosticCategories.PqcStage] = "A classical RSA or ECDSA key was submitted under a PQC stage; move the client to an ML-DSA, hybrid or composite key, or ask an admin for a time-limited exception.",
        [DiagnosticCategories.PolicyRejected] = "The template's issuance policy refused the request; its detail names the rule.",
        [DiagnosticCategories.CaNotReady] = "The CA is not initialized yet; approve the root CA request first.",
        [DiagnosticCategories.DuplicateCommonName] = "Another identity holds an active request for this name; revoke or reject it first.",
        [DiagnosticCategories.Disabled] = "The credential is disabled; enable it in Settings → EST or issue a new one.",
        [DiagnosticCategories.WrongSecret] = "The device sent the wrong password. Passwords cannot be read back; issue a new credential if it was lost.",
        [DiagnosticCategories.Revoked] = "The certificate presented for re-enrollment is revoked; enroll again with /simpleenroll.",
        [DiagnosticCategories.CompositeReenrollUnsupported] = "Re-enrollment cannot verify composite ML-DSA certificates or certificates issued by a composite CA; enroll again with /simpleenroll.",
        [DiagnosticCategories.IdentityMismatch] = "Re-enrollment must keep the names of the certificate presented; enroll with /simpleenroll for new names.",
    };

    /// <summary>The hint for <paramref name="category"/>, or null when it has none.</summary>
    public static string? For(string? category) => category is null ? null : Hints.GetValueOrDefault(category);
}
