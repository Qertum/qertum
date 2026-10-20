using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;

namespace Qertum.Services.Issuers;

/// <summary>
/// The consumer's "sign this approved request" step: pick the issuer (template pin, else default),
/// sign, and stamp which issuer signed. Root-CA requests create the CA instead — or, when filed by a
/// force generate, create a replacement root and destroy the default it was filed against.
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
        if (props?.ReplaceIssuerId is { } replaceId)
            return await ReplaceRootAsync(request, props, replaceId, ct);

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

    private async Task<GeneratedCertificate> ReplaceRootAsync(CertificateRequest request, RootCaProperties props, IssuerId replaceId, CancellationToken ct)
    {
        // Deterministic id: a retry after a failed DB write finds the files it already wrote.
        var replacement = new Issuer
        {
            Id = new IssuerId((Guid)request.Id), Name = "pending", Kind = IssuerKind.Root, KeyCustody = IssuerKeyCustody.Online,
            CreatedAtUtc = _clock.GetUtcNow().UtcDateTime
        };
        var existing = await issuers.GetAsync(replacement.Id, ct);
        if (existing is not null)
            return Result(existing.Issuer.CertificatePem!, existing.Issuer.Id); // installed by an earlier attempt

        // A stale request must never destroy a CA that changed after it was filed; the consumer
        // retries this and then rejects the request.
        var current = await issuers.GetDefaultAsync(ct);
        if (current is null || current.Issuer.Id != replaceId)
            throw new InvalidOperationException("The CA this request was filed to replace is no longer the default; file a new request.");

        var generator = new CertificateGenerator(dataProtection, storage.OptionsFor(replacement),
            loggerFactory.CreateLogger<CertificateGenerator>(), timeProvider: _clock);
        var pem = generator.IsInitialized
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

        IssuerCertificateFacts.Read(pem).ApplyTo(replacement);
        replacement.Name = await IssuerNames.UniqueAsync(db, request.CommonName, ct);
        replacement.CertificatePem = pem;
        await lifecycle.ReplaceDefaultAsync(current.Issuer, replacement, "queue-consumer", ct);
        return Result(pem, replacement.Id);

        static GeneratedCertificate Result(string certificatePem, IssuerId id)
        {
            var facts = IssuerCertificateFacts.Read(certificatePem);
            return new GeneratedCertificate
            {
                CertificatePem = certificatePem, SerialNumber = facts.SerialNumber,
                ValidFrom = facts.ValidFrom, ValidTo = facts.ValidTo, IssuerId = id
            };
        }
    }
}
