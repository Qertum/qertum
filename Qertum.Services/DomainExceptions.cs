namespace Qertum.Services;

public sealed class NotFoundException(string message) : Exception(message);

public sealed class InvalidStateTransitionException(
    CertificateRequestStatus current,
    CertificateRequestStatus target)
    : Exception($"Cannot transition from {current} to {target}.");

public sealed class DuplicateRequestException(string commonName)
    : Exception($"An active request for common name '{commonName}' already exists.");

/// <summary>A key algorithm the current PQC stage refuses. <see cref="Stage"/> selects 400 (create) or 422 (approval).</summary>
public sealed class PqcPolicyViolationException(string message, Policies.PolicyEnforcementStage stage = Policies.PolicyEnforcementStage.Create)
    : Exception(message)
{
    /// <summary>Where the refusal happened.</summary>
    public Policies.PolicyEnforcementStage Stage { get; } = stage;
}

/// <summary>
/// Thrown when a request that needs a signing CA is filed before the root CA exists. Root CA
/// requests themselves are exempt — approving one is what creates the CA.
/// </summary>
public class CaNotInitializedException : Exception
{
    public CaNotInitializedException()
        : base("The Root CA certificate has not been issued yet. Approve the Root CA request first; " +
               "certificate requests cannot be filed until the CA exists.") { }

    public CaNotInitializedException(string message) : base(message) { }
}

/// <summary>
/// The issuer a template is pinned to cannot sign (retired, archived, destroyed, pending, offline or
/// without a key). A <see cref="CaNotInitializedException"/> so every existing mapping — API 409,
/// ACME serverInternal, EST 503, consumer rejection — applies unchanged.
/// </summary>
public sealed class IssuerNotActiveException(string issuerName, IssuerStatus status)
    : CaNotInitializedException($"Issuer '{issuerName}' cannot issue certificates (status {status}). " +
                                "Pin the template to an active online issuer or clear its issuer.");

public sealed class DuplicateEstUsernameException(string username)
    : Exception($"An EST enrollment credential with username '{username}' already exists.");
