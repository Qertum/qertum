using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;
using OpenIddict.Validation;
using Qertum.IdentityService.Configuration;
using Qertum.ServiceDefaults.Secrets;

namespace Qertum.IdentityService.Services;

/// <summary>
/// The IdP's signing and encryption certificates as <see cref="IdentityCertificateStore"/> keeps them
/// under <c>keys/</c>, read on the injected clock. One instance feeds both OpenIddict's options and
/// the periodic rotation check, so they always agree on what "due" means.
/// </summary>
internal sealed class IdentityCertificateSource(
    string keysDirectory, IdentityServiceOptions options, ISecretProtector protector, TimeProvider clock)
{
    private const string SigningSubject = "CN=Qertum IDM Signing";
    private const string EncryptionSubject = "CN=Qertum IDM Encryption";

    /// <summary>Usable certificates per role, newest expiry first; creates a replacement when one is due.</summary>
    public (IReadOnlyList<X509Certificate2> Signing, IReadOnlyList<X509Certificate2> Encryption) Ensure()
    {
        var lifetime = TimeSpan.FromDays(options.CertificateLifetimeDays);
        var renewBefore = TimeSpan.FromDays(options.CertificateRenewBeforeDays);
        var now = clock.GetUtcNow();
        return (
            IdentityCertificateStore.EnsureCertificates(keysDirectory, IdentityCertificateStore.SigningRole,
                SigningSubject, lifetime, renewBefore, now, protector),
            IdentityCertificateStore.EnsureCertificates(keysDirectory, IdentityCertificateStore.EncryptionRole,
                EncryptionSubject, lifetime, renewBefore, now, protector));
    }
}

/// <summary>
/// Registers every still-valid certificate with OpenIddict each time its options are built. Built
/// once at startup, and again whenever <see cref="IdentityCertificateRotationService"/> clears the
/// cached options after the set of usable certificates changed.
/// </summary>
internal sealed class IdentityCertificateOptionsSetup(IdentityCertificateSource source)
    : IConfigureOptions<OpenIddictServerOptions>
{
    public void Configure(OpenIddictServerOptions options)
    {
        var (signing, encryption) = source.Ensure();

        // Same credentials OpenIddict's AddSigningCertificate / AddEncryptionCertificate build for
        // RSA certificates. Newest expiry first: OpenIddict signs with the first.
        foreach (var certificate in signing)
            options.SigningCredentials.Add(new SigningCredentials(new X509SecurityKey(certificate), SecurityAlgorithms.RsaSha256));

        foreach (var certificate in encryption)
            options.EncryptionCredentials.Add(new EncryptingCredentials(new X509SecurityKey(certificate),
                SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512));
    }
}

/// <summary>
/// Rotation while running: every <c>IdentityService:CertificateRotationCheckHours</c> it lets the
/// store create a due replacement, and when the usable set differs from what OpenIddict has
/// registered (a new key, or one that expired) it drops the cached server and validation options
/// so the next request rebuilds them — publishing the new key and dropping the expired one
/// without a restart.
/// </summary>
internal sealed class IdentityCertificateRotationService(
    IdentityCertificateSource source,
    IdentityServiceOptions identityOptions,
    IOptionsMonitor<OpenIddictServerOptions> serverOptions,
    IOptionsMonitorCache<OpenIddictServerOptions> serverOptionsCache,
    IOptionsMonitorCache<OpenIddictValidationOptions> validationOptionsCache,
    TimeProvider clock,
    ILogger<IdentityCertificateRotationService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromHours(identityOptions.CertificateRotationCheckHours);
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await Task.Delay(interval, clock, stoppingToken); }
            catch (OperationCanceledException) { break; }

            try
            {
                await CheckOnceAsync(stoppingToken);
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                // Registered keys stay as they are; the next tick tries again.
                logger.LogWarning(ex, "Identity certificate rotation check failed; retrying in {Interval}.", interval);
            }
        }
    }

    /// <summary>Returns true when the usable certificates changed and OpenIddict's options were rebuilt.</summary>
    internal Task<bool> CheckOnceAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // On disk first: a failure here leaves the registered keys untouched.
        var (signing, encryption) = source.Ensure();
        var usable = Thumbprints(signing.Concat(encryption));

        var current = serverOptions.CurrentValue;
        var registered = Thumbprints(
            current.SigningCredentials.Select(c => c.Key).Concat(current.EncryptionCredentials.Select(c => c.Key))
                .OfType<X509SecurityKey>().Select(k => k.Certificate));

        if (usable.SetEquals(registered))
            return Task.FromResult(false);

        // Server first: the validation options (UseLocalServer) are built from the server's.
        serverOptionsCache.TryRemove(Options.DefaultName);
        validationOptionsCache.TryRemove(Options.DefaultName);
        logger.LogInformation(
            "Identity certificates changed ({Added} added, {Removed} removed); OpenIddict keys reloaded.",
            usable.Except(registered).Count(), registered.Except(usable).Count());
        return Task.FromResult(true);
    }

    private static HashSet<string> Thumbprints(IEnumerable<X509Certificate2> certificates) =>
        certificates.Select(c => c.Thumbprint).ToHashSet(StringComparer.OrdinalIgnoreCase);
}
