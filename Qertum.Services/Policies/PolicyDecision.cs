namespace Qertum.Services.Policies;

public static class PolicyRules
{
    public const string Template = "template";
    public const string DnsSuffix = "dnsSuffix";
    public const string IpRange = "ipRange";
    public const string KeyAlgorithm = "keyAlgorithm";
    public const string MaxValidity = "maxValidity";

    /// <summary>The submitting caller holds none of the policy's allowed requester roles.</summary>
    public const string RequesterRole = "requesterRole";

    /// <summary>
    /// The key cannot do what the template's certificate must: a key that cannot sign (ML-KEM, or a
    /// signing + encryption pair whose second certificate is ML-KEM) under a template that asserts <c>KeyCertSign</c>. Not a policy rule an operator writes — it
    /// applies to every template, linked or not.
    /// </summary>
    public const string KeyCapability = "keyCapability";

    /// <summary>
    /// The policy requires a client-generated key and the request carries no CSR, so the CA would
    /// have to generate — and then hold — the private key.
    /// </summary>
    public const string KeyCustody = "keyCustody";

    /// <summary>The CA-wide PQC enforcement stage, not a policy rule — reported here so one preview lists every refusal.</summary>
    public const string PqcOnly = "pqcOnly";

    /// <summary>An active request already holds the common name.</summary>
    public const string DuplicateCommonName = "duplicateCommonName";

    /// <summary>Not an operator rule — the issuing CA's own certificate forbids it: a CA certificate below a path length limit.</summary>
    public const string IssuerPathLength = "issuerPathLength";

    /// <summary>Not an operator rule — the issuing CA's own certificate forbids it: a name outside a CA's NameConstraints.</summary>
    public const string IssuerNameConstraints = "issuerNameConstraints";

    /// <summary>Not an operator rule — the issuing CA's key backs a lower NIST level than the key it is asked to certify (<see cref="CaSettings.IssuerStrengthMode"/>).</summary>
    public const string IssuerStrength = "issuerStrength";

    /// <summary>The caller lacks <c>certificates.ca</c> for a template that issues a CA certificate (KeyCertSign).</summary>
    public const string CaPermission = "caPermission";

    /// <summary>The approver is the requester of a CA-capable request while independent approval is required.</summary>
    public const string SelfApproval = "selfApproval";
}

/// <summary>
/// Outcome of evaluating a request against its template's published policy. Every violation is
/// collected, not only the first, so callers can show the whole picture.
/// </summary>
public sealed record PolicyDecision(
    bool Allowed,
    Guid? PolicyVersionId,
    string? PolicyName,
    int? VersionNumber,
    IReadOnlyList<IssuancePolicyViolation> Violations)
{
    /// <summary>Allowed, with no policy governing the request.</summary>
    public static PolicyDecision Unrestricted { get; } = new(true, null, null, null, []);

    /// <summary>Notes that do not refuse the request (the issuer-strength rule under <see cref="IssuerStrengthMode.Warn"/>); empty when none.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    /// <summary>The listed requester role the submitting caller matched; null when not checked or admin.</summary>
    public string? MatchedRequesterRole { get; init; }

    /// <summary>A CA-capable request was approved by its own requester because independent approval is waived by setting.</summary>
    public bool SelfApprovalWaived { get; init; }

    /// <summary>The requester-role rule applied and the caller passed as admin.</summary>
    public bool RequesterIsAdmin { get; init; }

    /// <summary>The governing version lists requester roles (whether or not they were checked).</summary>
    public bool RequesterRolesListed { get; init; }

    public string Summarize()
    {
        var header = PolicyName is null
            ? "Issuance policy violation"
            : $"Issuance policy '{PolicyName}' v{VersionNumber} violation";
        return $"{header}: {string.Join("; ", Violations.Select(v => v.Message))}";
    }
}
