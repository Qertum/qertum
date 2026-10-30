using FluentValidation;
using Qertum.Services.Auth;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Qertum.Services.Crypto;
using Qertum.Services.Webhooks;

namespace Qertum.Services.Issuers;

/// <summary>
/// <c>/v1/issuers</c>: reads need certificates.view; the issuer certificate, chain and trust bundle
/// are anonymous (AIA caIssuers fetchers and trust bootstrap carry no credentials).
/// </summary>
public static class IssuerEndpointMappings
{
    public static RouteGroupBuilder MapIssuerApi(this RouteGroupBuilder v1)
    {
        var group = v1.MapGroup("/issuers").WithTags("Issuers");

        // validOnly leaves out CAs whose chain is broken (IssuerQueries.Broken) and archived or destroyed ones; a
        // retired CA with a valid certificate (the old root after a renewal) and one awaiting its certificate stay.
        group.MapGet("/", async (IIssuerRegistry issuers, TimeProvider clock, CancellationToken ct, bool validOnly = false) =>
        {
            var all = await issuers.GetAllAsync(ct);
            var broken = validOnly ? IssuerQueries.Broken(all, clock.GetUtcNow().UtcDateTime).Ids : [];
            return Results.Ok(all
                .Where(i => !validOnly || (!broken.Contains(i.Id) && i.Status is not (IssuerStatus.Archived or IssuerStatus.Destroyed)))
                .OrderBy(i => i.Kind == IssuerKind.Root ? 0 : 1).ThenBy(i => i.CreatedAtUtc)
                .Select(IssuerMapping.ToResponse));
        })
            .RequireAuthorization(AppPermissions.CertificatesView);

        group.MapGet("/{id:guid}", async (Guid id, IIssuerRegistry issuers, CancellationToken ct) =>
            await issuers.GetAsync(new IssuerId(id), ct) is { } handle
                ? Results.Ok(IssuerMapping.ToResponse(handle.Issuer))
                : ApiProblem.NotFound())
            .RequireAuthorization(AppPermissions.CertificatesView);

        group.MapGet("/{id:guid}/certificate", async (Guid id, [FromQuery] string? format, IIssuerRegistry issuers, CancellationToken ct) =>
        {
            var pem = (await issuers.GetAsync(new IssuerId(id), ct))?.Issuer.CertificatePem;
            if (pem is null) return ApiProblem.NotFound();
            return string.Equals(format, "der", StringComparison.OrdinalIgnoreCase)
                ? Results.Bytes(Der(pem), "application/pkix-cert", "issuer.cer")
                : Results.Bytes(Encoding.ASCII.GetBytes(pem), "application/x-pem-file", "issuer.pem");
        }).AllowAnonymous();

        group.MapGet("/{id:guid}/chain", async (Guid id, [FromQuery] string? format, IIssuerRegistry issuers, CancellationToken ct) =>
        {
            var chain = await issuers.ChainForAsync(new IssuerId(id), ct);
            return chain.Count == 0 ? ApiProblem.NotFound() : Bundle(chain, format, "chain");
        }).AllowAnonymous();

        group.MapGet("/trust-bundle", async ([FromQuery] string? format, IIssuerRegistry issuers, CancellationToken ct) =>
        {
            var roots = new List<string>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var issuer in (await issuers.GetAllAsync(ct)).Where(i => i.Status is IssuerStatus.Active or IssuerStatus.Retired))
            {
                var chain = await issuers.ChainForAsync(issuer.Id, ct);
                if (chain.Count > 0 && seen.Add(chain[^1].Trim())) roots.Add(chain[^1]);
            }
            return roots.Count == 0 ? Results.Problem("No trust anchor is configured yet.", statusCode: 503) : Bundle(roots, format, "trust-bundle");
        }).AllowAnonymous();

        var admin = v1.MapGroup("/issuers").WithTags("Issuers").RequireAuthorization("admin-role");

        admin.MapPost("/intermediates", async (CreateIntermediateRequest request, IValidator<CreateIntermediateRequest> validator,
            IssuerCeremonyService ceremonies, HttpContext http, IIdentityClaimsMapper claims, CancellationToken ct) =>
        {
            var validation = await validator.ValidateAsync(request, ct);
            if (!validation.IsValid) return Results.ValidationProblem(validation.ToErrorDictionary());
            var outcome = await ceremonies.CreateIntermediateAsync(request, claims.GetName(http.User), ct);
            return ToResult(outcome, created => Results.Created($"/v1/issuers/{created.Issuer.Id}", created));
        });

        admin.MapPost("/{id:guid}/renew", async (Guid id, [FromBody(EmptyBodyBehavior = Microsoft.AspNetCore.Mvc.ModelBinding.EmptyBodyBehavior.Allow)] RenewIssuerRequest? body,
            IValidator<RenewIssuerRequest> validator, IssuerCeremonyService ceremonies, HttpContext http, IIdentityClaimsMapper claims,
            CancellationToken ct) =>
        {
            var request = body ?? new RenewIssuerRequest();
            var validation = await validator.ValidateAsync(request, ct);
            if (!validation.IsValid) return Results.ValidationProblem(validation.ToErrorDictionary());
            var outcome = await ceremonies.RenewIntermediateAsync(new IssuerId(id), request, claims.GetName(http.User), ct);
            // Signed at once: the replacement is already in place (200). Waiting for its certificate: a new pending issuer (201).
            return ToResult(outcome, renewed => renewed.RequestFile is null
                ? Results.Ok(renewed)
                : Results.Created($"/v1/issuers/{renewed.Issuer.Id}", renewed));
        });

        admin.MapGet("/{id:guid}/request", async (Guid id, IssuerCeremonyService ceremonies, CancellationToken ct) =>
            ToResult(await ceremonies.GetRequestFileAsync(new IssuerId(id), ct), file => Results.Ok(file)));

        admin.MapPost("/{id:guid}/certificate", async (Guid id, InstallIssuerCertificateRequest body, IssuerCeremonyService ceremonies,
            HttpContext http, IIdentityClaimsMapper claims, CancellationToken ct) =>
            ToResult(await ceremonies.InstallCertificateAsync(new IssuerId(id), body, claims.GetName(http.User), ct), Results.Ok));

        admin.MapPost("/{id:guid}/crl", async (Guid id, HttpRequest request, IssuerCeremonyService ceremonies,
            HttpContext http, IIdentityClaimsMapper claims, CancellationToken ct) =>
        {
            const int limit = 1024 * 1024;
            if (request.ContentLength > limit) return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
            using var buffer = new MemoryStream();
            var chunk = new byte[81920];
            int read;
            while ((read = await request.Body.ReadAsync(chunk, ct)) > 0)
            {
                if (buffer.Length + read > limit) return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
                buffer.Write(chunk, 0, read);
            }
            return ToResult(await ceremonies.UploadCrlAsync(new IssuerId(id), buffer.ToArray(), claims.GetName(http.User), ct), Results.Ok);
        });

        admin.MapPost("/{id:guid}/make-default", async (Guid id, IssuerLifecycleService lifecycle, HttpContext http, IIdentityClaimsMapper claims, CancellationToken ct) =>
            ToResult(await lifecycle.MakeDefaultAsync(new IssuerId(id), claims.GetName(http.User), ct), Results.Ok));
        admin.MapPost("/{id:guid}/retire", async (Guid id, IssuerLifecycleService lifecycle, HttpContext http, IIdentityClaimsMapper claims, CancellationToken ct) =>
            ToResult(await lifecycle.RetireAsync(new IssuerId(id), claims.GetName(http.User), ct), Results.Ok));
        admin.MapPost("/{id:guid}/archive", async (Guid id, IssuerLifecycleService lifecycle, HttpContext http, IIdentityClaimsMapper claims, CancellationToken ct) =>
            ToResult(await lifecycle.ArchiveAsync(new IssuerId(id), claims.GetName(http.User), ct), Results.Ok));

        admin.MapDelete("/{id:guid}", async (Guid id, IssuerCeremonyService ceremonies, HttpContext http, IIdentityClaimsMapper claims, CancellationToken ct) =>
            ToResult(await ceremonies.DeletePendingAsync(new IssuerId(id), claims.GetName(http.User), ct), _ => Results.NoContent()));

        // The CA's own signing key leaves the server only here. Admin role, step-up and (when on) a second person's
        // approval gate it; the Web page and the docs say plainly that this is not a safe way to keep a CA key.
        admin.MapGet("/{id:guid}/private-key", async (Guid id, IIssuerRegistry issuers, IssuerKeyExporter exporter,
            IAuditLogService audit, IWebhookService webhooks, HttpContext http, IIdentityClaimsMapper claims, CancellationToken ct) =>
        {
            if (await issuers.GetAsync(new IssuerId(id), ct) is not { } handle || exporter.ReadKeyPem(handle.Issuer) is not { } keyPem)
                return ApiProblem.NotFound("This server holds no private key for that issuer.");

            var performedBy = claims.GetName(http.User);
            await audit.LogAsync("IssuerKeyDownloaded", performedBy, id, handle.Issuer.Name, "Private key", ct);
            await EnqueueKeyEgressAsync(webhooks, WellKnownWebhookEvents.IssuerKeyDownloaded, performedBy, handle.Issuer, ct);
            return Results.Bytes(Encoding.ASCII.GetBytes(keyPem), "application/x-pem-file", $"{ApiEndpointMappings.SafeFileName(handle.Issuer.Name)}.key");
        });

        admin.MapPost("/{id:guid}/pfx", async (Guid id, ExportIssuerPfxRequest body, IIssuerRegistry issuers, IssuerKeyExporter exporter,
            IAuditLogService audit, IWebhookService webhooks, HttpContext http, IIdentityClaimsMapper claims, CancellationToken ct) =>
        {
            if (await issuers.GetAsync(new IssuerId(id), ct) is not { } handle || exporter.ReadKeyPem(handle.Issuer) is not { } keyPem
                || handle.Issuer.CertificatePem is not { } certPem)
                return ApiProblem.NotFound("This server holds no private key for that issuer.");

            // The CAs above the issuer; the issuer's own certificate is the leaf of the bundle.
            var chain = body.IncludeChain ? (await issuers.ChainForAsync(handle.Issuer.Id, ct)).Skip(1).ToList() : [];
            byte[] pfx;
            try
            {
                pfx = QertumKeyCodec.ExportPkcs12(certPem, keyPem, chain, body.Password, handle.Issuer.Name);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or Org.BouncyCastle.Crypto.CryptoException
                                           or Org.BouncyCastle.Security.SecurityUtilityException)
            {
                return Results.Problem($"Cannot export this issuer as PKCS#12: {ex.Message}", statusCode: 400);
            }

            var performedBy = claims.GetName(http.User);
            await audit.LogAsync("IssuerPfxExported", performedBy, id, handle.Issuer.Name,
                body.IncludeChain ? "PKCS#12 with CA chain" : "PKCS#12", ct);
            await EnqueueKeyEgressAsync(webhooks, WellKnownWebhookEvents.IssuerPfxExported, performedBy, handle.Issuer, ct);
            return Results.Bytes(pfx, "application/x-pkcs12", $"{ApiEndpointMappings.SafeFileName(handle.Issuer.Name)}.pfx");
        });

        return v1;
    }

    /// <summary>KeyAccess carries no issuer id or name (WebhookService suppresses both); the thumbprint names the key that left.</summary>
    private static Task EnqueueKeyEgressAsync(IWebhookService webhooks, string eventName, string performedBy, Issuer issuer, CancellationToken ct) =>
        webhooks.EnqueueEventAsync(new WebhookEvent(eventName, PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["publicKeyThumbprint"] = PublicKeyThumbprint.FromCertificatePem(issuer.CertificatePem)
            }), ct);

    internal static IResult ToResult<T>(IssuerOutcome<T> outcome, Func<T, IResult> ok) => outcome.Refusal switch
    {
        null => ok(outcome.Value!),
        IssuerRefusal.NotFound => ApiProblem.NotFound(outcome.Message!),
        IssuerRefusal.Conflict => ApiProblem.Conflict(outcome.Message!),
        _ => ApiProblem.BadRequest(outcome.Message!)
    };

    internal static IResult Bundle(IReadOnlyList<string> pems, string? format, string name)
    {
        if (string.Equals(format, "p7b", StringComparison.OrdinalIgnoreCase))
        {
            var collection = new X509Certificate2Collection();
            foreach (var pem in pems) collection.Add(X509CertificateLoader.LoadCertificate(Der(pem)));
            return Results.Bytes(collection.Export(X509ContentType.Pkcs7)!, "application/x-pkcs7-certificates", $"{name}.p7b");
        }
        var text = string.Concat(pems.Select(p => p.Trim() + "\n"));
        return Results.Bytes(Encoding.ASCII.GetBytes(text), "application/x-pem-file", $"{name}.pem");
    }

    /// <summary>DER through BouncyCastle: the BCL cannot parse a composite certificate from PEM.</summary>
    private static byte[] Der(string pem) =>
        (QertumKeyCodec.ReadCertificatePem(pem) ?? throw new CryptographicException("Stored issuer certificate is unreadable.")).GetEncoded();
}
