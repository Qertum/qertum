using Qertum.ServiceDefaults.Secrets;

namespace Qertum.IdentityService.Configuration;

/// <summary>
/// Configuration for the identity provider itself, bound from the "IdentityService" section.
/// Distinct from the consuming applications' "Identity" section, which names the issuer they
/// trust; this type is how the issuer describes itself.
/// </summary>
public sealed class IdentityServiceOptions
{
    public const string SectionName = "IdentityService";

    /// <summary>
    /// Absolute URL this provider advertises as its issuer. Written into the "iss" claim and
    /// the discovery document, so it must match what consumers configure as Identity:Authority.
    /// </summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>
    /// Directory holding users.json, clients.json, identity.db, and keys/. Defaults to the
    /// application base directory, which is wrong for any container with a mounted volume —
    /// deployments must set this explicitly.
    /// </summary>
    public string? DataPath { get; set; }

    /// <summary>
    /// Opts out of OpenIddict's HTTPS transport requirement. Needed when TLS is terminated by
    /// a reverse proxy or not used at all on a trusted network.
    /// </summary>
    public bool DisableTransportSecurity { get; set; }

    /// <summary>
    /// Whether redirect URIs read from the service-discovery variables
    /// (Services:webfrontend:{https,http}:0) are added to the qertum-web client on top of
    /// clients.json. Null means "Development only", because those variables are normally an
    /// Aspire-only artifact. A deployment that injects them itself — deploy/single-container
    /// does — must set this to true explicitly, or its redirect URIs are silently dropped.
    /// </summary>
    public bool? EnableServiceDiscoveryRedirectUris { get; set; }

    /// <summary>
    /// Overrides the generated qertum-api client secret during seeding. Injected by the Aspire
    /// AppHost so local runs are deterministic; unset in production, where the secret is
    /// generated once and persisted to clients.json.
    /// </summary>
    public string? ApiClientSecret { get; set; }

    /// <summary>
    /// Password given to the seeded <c>admin</c> user on first run, when users.json does not
    /// yet exist. When unset, <c>JsonUserStore.DefaultAdminPassword</c> is used instead and
    /// the seeded account is flagged to require a password change at first login. Read only
    /// during seeding — changing it later has no effect on an existing users.json.
    /// </summary>
    public string? SeedAdminPassword { get; set; }

    /// <summary>
    /// Seed the integration-test clients (<c>qertum-test-m2m</c>, <c>qertum-test-viewer</c>), whose
    /// secrets are committed to this repository. Only the Aspire integration fixture sets it; every start
    /// without it also removes those clients.
    /// </summary>
    public bool SeedTestClients { get; set; }

    /// <summary>
    /// Which provider protects the key files in <c>keys/</c>. Null keeps whatever
    /// <c>secret-storage.json</c> under <see cref="DataPath"/> records (a fresh volume: the local
    /// file key). A different value re-encrypts <c>keys/</c> at startup and records it — see
    /// <c>IdentitySecretStorageMigration</c>.
    /// </summary>
    public SecretStorageProvider? SecretStorageProvider { get; set; }

    /// <summary>
    /// Validity window, in days, for the provider's own signing and encryption certificates.
    /// Defaults to five years. Applies only to certificates created from now on; existing ones
    /// keep the lifetime they were issued with.
    /// </summary>
    public int CertificateLifetimeDays { get; set; } = 1825;

    /// <summary>
    /// How many days before expiry a replacement certificate is created. Defaults to 90.
    /// Doubles as the overlap window: the retiring certificate stays published in the JWKS
    /// document for this long, so tokens signed with it keep validating. Must be shorter than
    /// <see cref="CertificateLifetimeDays"/> and longer than the longest refresh-token lifetime,
    /// or tokens issued just before a rotation can outlive the key that signed them.
    /// </summary>
    public int CertificateRenewBeforeDays { get; set; } = 90;

    /// <summary>
    /// How often a running IdP checks whether a certificate replacement is due or a key expired,
    /// and reloads OpenIddict's keys when so. Defaults to 24.
    /// </summary>
    public int CertificateRotationCheckHours { get; set; } = 24;

    /// <summary>Audit log of user and role administration.</summary>
    public IdentityAuditLogOptions AuditLog { get; set; } = new();

    private string? _resolvedDataPath;

    /// <summary>Resolved value of <see cref="EnableServiceDiscoveryRedirectUris"/> after validation.</summary>
    public bool ServiceDiscoveryRedirectUrisEnabled => EnableServiceDiscoveryRedirectUris ?? false;

    /// <summary>
    /// Validates the configuration, normalizes <see cref="Authority"/>, and resolves the
    /// service-discovery default for the current environment.
    /// </summary>
    /// <exception cref="InvalidOperationException">Configuration is missing or inconsistent.</exception>
    public void Validate(bool isDevelopment)
    {
        EnableServiceDiscoveryRedirectUris ??= isDevelopment;

        // A blank value means "not configured": deploy/single-container/entrypoint.sh
        // exports the variable unconditionally with an empty default, and that must behave
        // exactly like omitting it rather than failing the length check below.
        if (string.IsNullOrWhiteSpace(SeedAdminPassword))
        {
            SeedAdminPassword = null;
        }
        else if (SeedAdminPassword.Length < 8)
        {
            throw new InvalidOperationException(
                "IdentityService:SeedAdminPassword must be at least 8 characters.");
        }

        if (SecretStorageProvider == Qertum.ServiceDefaults.Secrets.SecretStorageProvider.CloudStub)
        {
            throw new InvalidOperationException(
                "IdentityService:SecretStorageProvider 'CloudStub' is not implemented; use LocalFileKey or LocalTpm.");
        }

        if (CertificateLifetimeDays <= 0)
        {
            throw new InvalidOperationException(
                "IdentityService:CertificateLifetimeDays must be greater than zero.");
        }

        if (CertificateRenewBeforeDays <= 0 || CertificateRenewBeforeDays >= CertificateLifetimeDays)
        {
            throw new InvalidOperationException(
                "IdentityService:CertificateRenewBeforeDays must be greater than zero and less than " +
                $"IdentityService:CertificateLifetimeDays ({CertificateLifetimeDays}); otherwise a " +
                "newly created certificate is immediately due for replacement.");
        }

        if (CertificateRotationCheckHours <= 0)
        {
            throw new InvalidOperationException(
                "IdentityService:CertificateRotationCheckHours must be greater than zero.");
        }

        if (string.IsNullOrWhiteSpace(Authority))
        {
            if (isDevelopment)
            {
                // Development falls back to the address Kestrel happens to bind, which
                // OpenIddict infers per request. That inference is exactly what breaks behind
                // a proxy, so it is not allowed anywhere else.
                return;
            }

            throw new InvalidOperationException(
                "IdentityService:Authority is not configured. Set it to the absolute URL this " +
                "provider is reached at, for example https://idp.example. Consumers must " +
                "configure the same value as Identity:Authority.");
        }

        if (!Uri.TryCreate(Authority, UriKind.Absolute, out var authorityUri))
        {
            throw new InvalidOperationException(
                $"IdentityService:Authority ('{Authority}') must be an absolute URL, " +
                "for example https://idp.example.");
        }

        // Deliberately no "HTTPS outside Development" rule here, unlike the consumer-side
        // Identity:Authority: this provider is routinely fronted by a TLS-terminating proxy
        // and reached over plain HTTP on a trusted network. The scheme still has to be one
        // an OIDC client can dereference.
        if (authorityUri.Scheme != Uri.UriSchemeHttp && authorityUri.Scheme != Uri.UriSchemeHttps)
        {
            throw new InvalidOperationException(
                $"IdentityService:Authority ('{Authority}') must use the http or https scheme, " +
                "for example https://idp.example.");
        }

        Authority = Authority.TrimEnd('/');
    }

    /// <summary>
    /// Returns the absolute data directory, creating it if absent. Idempotent.
    /// </summary>
    public string ResolveDataPath()
    {
        if (_resolvedDataPath is not null)
        {
            return _resolvedDataPath;
        }

        var path = string.IsNullOrWhiteSpace(DataPath)
            ? AppContext.BaseDirectory
            : DataPath;

        var absolute = Path.GetFullPath(path);
        Directory.CreateDirectory(absolute);

        _resolvedDataPath = absolute;
        return absolute;
    }

    /// <summary>
    /// Absolute audit log path: <see cref="IdentityAuditLogOptions.Path"/> when set, otherwise under
    /// the data path so a mounted volume keeps it across redeploys.
    /// </summary>
    public string ResolveAuditLogPath() =>
        string.IsNullOrWhiteSpace(AuditLog.Path)
            ? Path.Combine(ResolveDataPath(), "audit-logs", "identity-audit-.clef")
            : Path.GetFullPath(AuditLog.Path);
}
