using Microsoft.EntityFrameworkCore;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;

namespace Qertum.Services.Issuers;

/// <summary>
/// The consumer's "sign this approved request" step: pick the issuer (template pin, else default),
/// sign, and stamp which issuer signed. Root-CA requests create the CA instead — or, when filed by a
/// force generate, create a replacement root and destroy the default it was filed against; a renewal of a
/// root creates a new root key that becomes the default and retires (never destroys) the renewed one.
/// </summary>
public sealed class IssuanceSigner(
    IIssuerRegistry issuers,
    ICertificateTemplateService templates,
    ICertificateGenerator legacy,
    IssuerStorage storage,
    IDataProtectionProvider dataProtection,
    ILoggerFactory loggerFactory,
    IssuerLifecycleService lifecycle,
    CertificateRequestDbContext db,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    public async Task<GeneratedCertificate> SignAsync(CertificateRequest request, CaSettings settings, CancellationToken ct)
    {
        if (request.Type == WellKnownCertificateTypes.RootCa)
            return await CreateRootAsync(request, ct);

        var template = await templates.GetByTypeKeyAsync(request.Type ?? "WebServer", ct);
        var handle = await issuers.ForIssuanceAsync(template, ct);
        var urls = IssuerUrls.For(handle.Issuer, settings);
        var generated = request.CsrPem is not null
            ? handle.Generator!.GenerateFromCsr(request.CsrPem, request, settings, template, urls)
            : handle.Generator!.GenerateCertificate(request, settings, template, urls);
        generated.IssuerId = handle.RecordedIssuerId;
        return generated;
    }

    private async Task<GeneratedCertificate> CreateRootAsync(CertificateRequest request, CancellationToken ct)
    {
        var props = string.IsNullOrEmpty(request.PropertiesJson)
            ? null
            : JsonSerializer.Deserialize<RootCaProperties>(request.PropertiesJson);
        if (request.RenewedFromId is { } renewedFrom)
            return await RenewRootAsync(request, props, renewedFrom, ct);
        if (props?.ReplaceIssuerId is { } replaceId)
            return await ReplaceRootAsync(request, props, replaceId, ct);
        if (props?.AfterRevokedIssuer == true)
            return await ReplaceRootAsync(request, props, replaceId: null, ct);

        GeneratedCertificate generated;
        if (legacy.IsInitialized)
        {
            // Idempotent retry: the files were written by an earlier attempt whose DB write failed.
            var existing = legacy.GetCaStatus();
            var now = _clock.GetUtcNow().UtcDateTime;
            generated = new GeneratedCertificate
            {
                CertificatePem = legacy.GetCaCertificatePem(),
                ValidFrom = existing.ValidFrom ?? now,
                ValidTo = existing.ValidTo ?? now.AddYears(10)
            };
        }
        else
        {
            generated = legacy.GenerateCa(new GenerateCaRequest
            {
                CommonName = request.CommonName,
                OrganizationName = props?.OrganizationName,
                OrganizationalUnit = props?.OrganizationalUnit,
                Country = props?.Country,
                State = props?.State,
                Locality = props?.Locality,
                ValidityDays = props?.ValidityDays ?? 3650,
                KeyAlgorithm = request.KeyAlgorithm ?? CertificateKeyAlgorithm.Rsa
            });
        }

        await issuers.InvalidateAsync(ct);
        generated.IssuerId = (await issuers.GetDefaultAsync(ct))?.RecordedIssuerId;
        return generated;
    }

    /// <summary>
    /// A root renewal: always a new key, under the renewed root's name, registered as the default issuer. A revoked
    /// root is renewed into the empty default seat; a live one must still hold it. If either changed after the
    /// renewal was filed (a new CA set up, another issuer made default), it is refused, never overridden.
    /// </summary>
    private async Task<GeneratedCertificate> RenewRootAsync(CertificateRequest request, RootCaProperties? props,
        CertificateRequestId renewedFrom, CancellationToken ct)
    {
        var replacement = NewRoot(request);
        if (await issuers.GetAsync(replacement.Id, ct) is { } installed)
            return Installed(installed.Issuer.CertificatePem!, installed.Issuer.Id); // installed by an earlier attempt

        var source = await db.CertificateRequests.AsNoTracking().FirstOrDefaultAsync(r => r.Id == renewedFrom, ct);
        var renewed = source is null ? null : await IssuerQueries.RootIssuerOfAsync(db, source, ct);
        if (renewed is null)
            throw new InvalidOperationException("The root CA this request renews no longer exists; set up a new CA instead.");

        var current = await issuers.GetDefaultAsync(ct);
        var expected = renewed.RevokedAtUtc is null ? renewed.Id : (IssuerId?)null;
        if (current?.Issuer.Id != expected)
            throw new InvalidOperationException(renewed.RevokedAtUtc is null
                ? $"'{renewed.Name}' is no longer the default issuer; renew the current one instead."
                : "A new CA was set up after this renewal was filed; it would no longer replace anything.");

        var pem = GenerateRoot(replacement, request, props ?? new RootCaProperties());
        IssuerCertificateFacts.Read(pem).ApplyTo(replacement);
        // A renewal is the same CA under a new key, so it keeps the name; serial, thumbprint and dates tell them apart.
        replacement.Name = renewed.Name;
        replacement.RenewalOfIssuerId = renewed.Id; // intermediate renewals follow this to sign under the new root
        replacement.CertificatePem = pem;
        await lifecycle.RenewRootAsync(renewed, replacement, "queue-consumer", ct);
        return Installed(pem, replacement.Id);
    }

    private Issuer NewRoot(CertificateRequest request) => new()
    {
        // Deterministic id: a retry after a failed DB write finds the files it already wrote.
        Id = new IssuerId((Guid)request.Id), Name = "pending", Kind = IssuerKind.Root, KeyCustody = IssuerKeyCustody.Online,
        CreatedAtUtc = _clock.GetUtcNow().UtcDateTime
    };

    /// <summary>A new root key and self-signed certificate in <paramref name="issuer"/>'s own directory (kept on a retry).</summary>
    private string GenerateRoot(Issuer issuer, CertificateRequest request, RootCaProperties props)
    {
        var generator = new CertificateGenerator(dataProtection, storage.OptionsFor(issuer),
            loggerFactory.CreateLogger<CertificateGenerator>(), timeProvider: _clock);
        return generator.IsInitialized
            ? generator.GetCaCertificatePem()
            : generator.GenerateCa(new GenerateCaRequest
            {
                CommonName = request.CommonName,
                OrganizationName = props.OrganizationName,
                OrganizationalUnit = props.OrganizationalUnit,
                Country = props.Country,
                State = props.State,
                Locality = props.Locality,
                ValidityDays = props.ValidityDays,
                KeyAlgorithm = request.KeyAlgorithm ?? CertificateKeyAlgorithm.Rsa
            }).CertificatePem;
    }

    private static GeneratedCertificate Installed(string certificatePem, IssuerId id)
    {
        var facts = IssuerCertificateFacts.Read(certificatePem);
        return new GeneratedCertificate
        {
            CertificatePem = certificatePem, SerialNumber = facts.SerialNumber,
            ValidFrom = facts.ValidFrom, ValidTo = facts.ValidTo, IssuerId = id
        };
    }

    private async Task<GeneratedCertificate> ReplaceRootAsync(CertificateRequest request, RootCaProperties props, IssuerId? replaceId, CancellationToken ct)
    {
        var replacement = NewRoot(request);
        var existing = await issuers.GetAsync(replacement.Id, ct);
        if (existing is not null)
            return Installed(existing.Issuer.CertificatePem!, existing.Issuer.Id); // installed by an earlier attempt

        // A stale request must never destroy a CA that changed after it was filed; the consumer
        // retries this and then rejects the request.
        // The after-revocation form has no CA to replace: it is stale as soon as any default exists.
        var current = await issuers.GetDefaultAsync(ct);
        if (replaceId is null ? current is not null : current is null || current.Issuer.Id != replaceId)
            throw new InvalidOperationException("The CA this request was filed to replace is no longer the default; file a new request.");

        var pem = GenerateRoot(replacement, request, props);

        IssuerCertificateFacts.Read(pem).ApplyTo(replacement);
        replacement.Name = await IssuerNames.UniqueAsync(db, request.CommonName, ct);
        replacement.CertificatePem = pem;
        if (current is null)
            await lifecycle.RegisterDefaultAsync(replacement, "queue-consumer", ct);
        else
            await lifecycle.ReplaceDefaultAsync(current.Issuer, replacement, "queue-consumer", ct);
        return Installed(pem, replacement.Id);
    }
}
