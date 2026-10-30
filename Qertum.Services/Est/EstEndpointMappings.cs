using Qertum.Services.Issuers;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1.X509;
using Qertum.Services.Lifecycle;

namespace Qertum.Services.Est;

/// <summary>
/// Maps the RFC 7030 EST endpoints under <c>/.well-known/est</c>.
/// </summary>
public static class EstEndpointMappings
{
    private const string Pkcs7MimeType = "application/pkcs7-mime";

    /// <summary>
    /// Template (and so issuance policy) an EST enrollment is filed under: whatever
    /// <see cref="CaSettings.EstTemplateTypeKey"/> names, falling back to <c>"WebServer"</c> for a
    /// settings row written before the key existed.
    /// </summary>
    private static string EstCertificateType(CaSettings settings) =>
        string.IsNullOrWhiteSpace(settings.EstTemplateTypeKey) ? "WebServer" : settings.EstTemplateTypeKey;

    /// <summary>
    /// Statuses that mean "still in flight" for the purposes of RFC 7030 §4.2.3's asynchronous
    /// enrollment: a client that resubmits an identical request gets its existing row's current
    /// response back, not a second row.
    /// </summary>
    public static IEndpointRouteBuilder MapEstEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/.well-known/est");

        // No auth (RFC 7030 §4.1): the CA certificate is public information, same trust boundary as
        // GET /ca/certificate.
        group.MapGet("/cacerts", async (IIssuerRegistry issuers, CancellationToken ct) =>
        {
            var certificates = await CaCertificatesAsync(issuers, ct);
            if (certificates.Count == 0) return Results.Problem("CA is not initialized.", statusCode: 503);
            try { return Results.Text(EstCmsHelper.BuildDegenerateCmsBase64(certificates), Pkcs7MimeType); }
            finally { foreach (var c in certificates) c.Dispose(); }
        });

        // Advisory only (RFC 7030 §4.5.2): an empty SEQUENCE OF AttrOrOID means "no specific
        // attributes requested". Nothing in Qertum has an opinion on CSR attributes yet.
        group.MapGet("/csrattrs", () =>
        {
            // DER encoding of an empty SEQUENCE: tag 0x30, length 0x00.
            var emptySequence = Convert.ToBase64String([0x30, 0x00]);
            return Results.Text(emptySequence, Pkcs7MimeType);
        });

        // RFC 7030 §4.2: CSR-based enrollment, gated on HTTP Basic auth against an
        // EstEnrollmentCredential. Flows through the normal Pending -> Approved -> Processing ->
        // Issued pipeline (CsrPem selects the CSR path), same shape as ACME's finalize.
        group.MapPost("/simpleenroll", async (
            HttpContext ctx,
            IEstEnrollmentCredentialService credentials,
            ICertificateRequestService certRequests,
            ICertificateApprovalQueue approvalQueue,
            CertificateRequestDbContext db,
            Microsoft.Extensions.Options.IOptions<EstOptions> estOptions,
            IDiagnosticEventLog diagnostics,
            CancellationToken ct) =>
        {
            // RFC 7030 §3.3.1 mandates HTTP Basic run only over TLS: it is trivially replayable
            // over plaintext. Only an operator who has decided TLS is terminated in front of this
            // service (a trusted reverse proxy) may opt out, same shape as other "may be behind a
            // proxy" toggles in this repo.
            // The TLS handshake of this very connection, not the request's scheme: EstService terminates TLS itself
            // and never trusts forwarded headers.
            if (estOptions.Value.RequireHttps && ctx.Features.Get<Microsoft.AspNetCore.Http.Features.ITlsConnectionFeature>() is null)
                return Unauthorized(ctx);

            var (authError, credentialId) = await TryAuthenticateBasicAsync(ctx, credentials, ct);
            if (authError is not null) return authError;

            var subjectId = credentialId!.Value;
            IResult Refuse(IResult response, string category, string detail)
            {
                diagnostics.Record(LifecycleSubjectTypes.EstCredential, subjectId, DiagnosticActions.EnrollmentRefused,
                    $"est:{subjectId}", category, detail);
                return response;
            }

            string csrBase64;
            try
            {
                csrBase64 = EnrollmentPayloadLimits.WithoutWhitespace(await EnrollmentPayloadLimits.ReadUtf8Async(ctx.Request,
                    EnrollmentPayloadLimits.EstBodyBytes, ct));
                EnrollmentPayloadLimits.DecodeBase64(csrBase64, EnrollmentPayloadLimits.CsrBytes);
            }
            catch (EnrollmentPayloadTooLargeException)
            {
                return Refuse(Results.StatusCode(StatusCodes.Status413PayloadTooLarge),
                    DiagnosticCategories.UnparseableCsr, "The CSR is too large.");
            }
            catch (FormatException)
            {
                return Refuse(Results.StatusCode(StatusCodes.Status400BadRequest),
                    DiagnosticCategories.UnparseableCsr, "The CSR could not be parsed.");
            }

            string commonName;
            IReadOnlyList<string> dnsNames;
            try
            {
                (commonName, dnsNames) = EstCsrHelper.ExtractIdentity(csrBase64);
            }
            catch (Exception)
            {
                return Refuse(Results.StatusCode(StatusCodes.Status400BadRequest), DiagnosticCategories.UnparseableCsr,
                    "The CSR could not be parsed.");
            }

            var settings = await certRequests.GetSettingsAsync(ct);

            var (algorithmError, detectedCsrAlgorithm) = DetectCsrAlgorithm(csrBase64);
            if (algorithmError is not null)
                return Refuse(algorithmError, DiagnosticCategories.KeyRefused, "The CSR's key algorithm is unsupported.");

            // Attribution: every request this credential files is scoped to it. This is what stops
            // one credential holder from retrieving another identity's certificate by guessing its
            // common name (the duplicate-CN lookup below is filtered by this same value), and what
            // lets a repeat enrollment for a CN this credential already holds be recognized as a
            // renewal instead of colliding with the global active-CN uniqueness rule.
            var enrollerIdentity = $"est:{credentialId}";

            var existingForRetry = await db.CertificateRequests
                .AsNoTracking()
                .Where(r => r.RequestedBySubject == enrollerIdentity &&
                            r.CsrPem == csrBase64 &&
                            r.Status != CertificateRequestStatus.Rejected &&
                            r.Status != CertificateRequestStatus.Revoked)
                .OrderByDescending(r => r.CreatedAtUtc)
                .FirstOrDefaultAsync(ct);

            if (existingForRetry is not null)
                return await RespondForRequestStatusAsync(existingForRetry, ct);

            var existingForIdentity = await db.CertificateRequests
                .AsNoTracking()
                .Where(r => r.CommonName == commonName &&
                            r.RequestedBySubject == enrollerIdentity &&
                            r.Status != CertificateRequestStatus.Rejected &&
                            r.Status != CertificateRequestStatus.Revoked)
                .OrderByDescending(r => r.CreatedAtUtc)
                .FirstOrDefaultAsync(ct);

            // Only an issued request can be renewal source. A different CSR while an earlier
            // request is active remains subject to the active-common-name rule.
            var renewedFromId = existingForIdentity?.Status == CertificateRequestStatus.Issued
                ? (CertificateRequestId?)existingForIdentity.Id
                : null;

            var certRequest = new CertificateRequest
            {
                CommonName = commonName,
                RequestedBy = enrollerIdentity,
                RequestedBySubject = enrollerIdentity,
                RenewedFromId = renewedFromId,
                Type = EstCertificateType(settings),
                PropertiesJson = System.Text.Json.JsonSerializer.Serialize(new { dnsNames }),
                Status = settings.EstAutoApprove ? CertificateRequestStatus.Approved : CertificateRequestStatus.Pending,
                KeyAlgorithm = detectedCsrAlgorithm,
                CsrPem = csrBase64
            };

            CertificateRequest created;
            try
            {
                created = await certRequests.CreateAsync(certRequest, enrollerIdentity, nameof(CaSettings.EstAutoApprove), ct);
            }
            catch (Policies.IssuancePolicyViolationException ex)
            {
                // RFC 7030 defines no policy error; a plain 400 with the violations, same shape as
                // the algorithm check above, tells the device operator what to change.
                return Refuse(Results.BadRequest(new { error = ex.Message, violations = ex.Decision.Violations }),
                    DiagnosticCategories.PolicyRejected, ex.Message);
            }
            catch (PqcPolicyViolationException ex)
            {
                return Refuse(Results.BadRequest(new { error = ex.Message }), DiagnosticCategories.KeyRefused, ex.Message);
            }
            catch (CaNotInitializedException ex)
            {
                // Nothing can be signed before the CA exists. 503 tells the device this is a server
                // state it may retry, unlike the 400s above which are the client's to fix.
                return Refuse(Results.Problem(ex.Message, statusCode: 503), DiagnosticCategories.CaNotReady, ex.Message);
            }
            catch (DuplicateRequestException)
            {
                // The active-common-name index is global, not scoped by identity: another
                // credential already holds an active request for this CN, or two enrollments for a
                // first-time name raced. Either way this is a client-visible collision, and handing
                // back the other identity's certificate would be a cross-tenant leak — refuse it
                // instead of resolving it the way the same-identity resubmission path above does.
                var duplicate = $"An active certificate request already exists for '{commonName}'.";
                return Refuse(Results.Conflict(new { error = duplicate }), DiagnosticCategories.DuplicateCommonName, duplicate);
            }

            if (settings.EstAutoApprove)
                approvalQueue.TrySignal();
            diagnostics.Record(LifecycleSubjectTypes.EstCredential, subjectId, DiagnosticActions.Enrolled, enrollerIdentity,
                detail: $"Enrolled {commonName}.",
                data: new { certificateRequestId = (Guid)created.Id, autoApproved = settings.EstAutoApprove });

            return await RespondForRequestStatusAsync(created, ct);
        })
        .CountEnrollments(EstEnrollmentMetricsFilter.Enroll)
        .RequireRateLimiting(EstRateLimiting.PolicyName);

        // RFC 7030 §4.2.2: mTLS-authenticated renewal. The client presents its current EST-issued
        // certificate as the TLS client certificate; we verify it chains to this CA's root and is
        // not Revoked before accepting the renewal CSR. Flows through the same pipeline as
        // /simpleenroll otherwise.
        group.MapPost("/simplereenroll", async (
            HttpContext ctx,
            IIssuerRegistry issuers,
            ICertificateRequestService certRequests,
            ICertificateApprovalQueue approvalQueue,
            CertificateRequestDbContext db,
            IDiagnosticEventLog diagnostics,
            CancellationToken ct) =>
        {
            if (ctx.Request.ContentLength > EnrollmentPayloadLimits.EstBodyBytes)
                return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
            var clientCert = ctx.Connection.ClientCertificate;
            if (clientCert is null) return Results.StatusCode(StatusCodes.Status401Unauthorized);

            // Every Active/Retired issuer path is trusted: a device keeps re-enrolling through a rollover.
            var (anchors, intermediates) = await TrustSetAsync(issuers, ct);
            using var trust = new TrustSet(anchors, intermediates);
            if (anchors.Count == 0) return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);

            var presentedSerialForRecord = NormalizeSerial(clientCert.SerialNumber);
            // Recorded against the certificate the device presented, when it is one this CA issued, so
            // the refusal shows on that certificate's timeline. A certificate that names nothing we
            // issued goes nowhere: there is no subject to attach it to.
            async Task<IResult> RefuseAsync(IResult response, string category, string detail)
            {
                var requestId = await db.CertificateRequests.AsNoTracking()
                    .Where(r => r.SerialNumber == presentedSerialForRecord)
                    .Select(r => r.Id)
                    .FirstOrDefaultAsync(ct);
                if (requestId != default)
                    diagnostics.Record(LifecycleSubjectTypes.CertificateRequest, requestId, DiagnosticActions.ReenrollRefused,
                        $"est-cert:{presentedSerialForRecord}", category, detail);
                return response;
            }

            // .NET's X509Chain cannot verify a composite ML-DSA signature, so VerifyReenrollCertificateAsync
            // would report such a certificate as "does not chain". Say what actually happened instead.
            if (anchors.Concat(intermediates).Any(ca => InvolvesCompositeSignature(clientCert, ca)))
                return await RefuseAsync(Results.StatusCode(StatusCodes.Status401Unauthorized),
                    DiagnosticCategories.CompositeReenrollUnsupported,
                    "Re-enrollment cannot verify a composite ML-DSA certificate or a certificate issued by a composite CA.");

            var verifyResult = await VerifyReenrollCertificateAsync(clientCert, anchors, intermediates, certRequests, ct);
            if (!verifyResult)
                return await RefuseAsync(Results.StatusCode(StatusCodes.Status401Unauthorized), DiagnosticCategories.Revoked,
                    "The certificate presented for re-enrollment is revoked or does not chain to this CA.");

            string csrBase64;
            try
            {
                csrBase64 = EnrollmentPayloadLimits.WithoutWhitespace(await EnrollmentPayloadLimits.ReadUtf8Async(ctx.Request,
                    EnrollmentPayloadLimits.EstBodyBytes, ct));
                EnrollmentPayloadLimits.DecodeBase64(csrBase64, EnrollmentPayloadLimits.CsrBytes);
            }
            catch (EnrollmentPayloadTooLargeException)
            {
                return await RefuseAsync(Results.StatusCode(StatusCodes.Status413PayloadTooLarge),
                    DiagnosticCategories.UnparseableCsr, "The CSR is too large.");
            }
            catch (FormatException)
            {
                return await RefuseAsync(Results.StatusCode(StatusCodes.Status400BadRequest),
                    DiagnosticCategories.UnparseableCsr, "The CSR could not be parsed.");
            }

            string commonName;
            IReadOnlyList<string> dnsNames;
            try
            {
                (commonName, dnsNames) = EstCsrHelper.ExtractIdentity(csrBase64);
            }
            catch (Exception)
            {
                return await RefuseAsync(Results.StatusCode(StatusCodes.Status400BadRequest), DiagnosticCategories.UnparseableCsr,
                    "The CSR could not be parsed.");
            }

            // The CSR is unauthenticated on its own — only the mTLS proof is. Without this check,
            // any certificate this CA ever issued could be presented to enroll a CSR for a
            // completely unrelated name.
            if (!CsrIdentityMatchesCertificate(commonName, dnsNames, clientCert))
                return await RefuseAsync(Results.StatusCode(StatusCodes.Status403Forbidden), DiagnosticCategories.IdentityMismatch,
                    "The CSR names differ from the certificate presented.");

            var settings = await certRequests.GetSettingsAsync(ct);

            var (algorithmError, detectedCsrAlgorithm) = DetectCsrAlgorithm(csrBase64);
            if (algorithmError is not null)
                return await RefuseAsync(algorithmError, DiagnosticCategories.KeyRefused, "The CSR's key algorithm is unsupported.");

            var presentedSerial = NormalizeSerial(clientCert.SerialNumber);
            var reenrollIdentity = $"est-cert:{presentedSerial}";

            var existingForRetry = await db.CertificateRequests
                .AsNoTracking()
                .Where(r => r.RequestedBySubject == reenrollIdentity &&
                            r.CsrPem == csrBase64 &&
                            r.Status != CertificateRequestStatus.Rejected &&
                            r.Status != CertificateRequestStatus.Revoked)
                .OrderByDescending(r => r.CreatedAtUtc)
                .FirstOrDefaultAsync(ct);

            if (existingForRetry is not null)
                return await RespondForRequestStatusAsync(existingForRetry, ct);

            // The certificate actually being renewed: the request whose issued serial matches the
            // one just presented over mTLS. This is what CreateAsync needs to skip the active-CN
            // check and treat the new row as a genuine renewal rather than a duplicate of the
            // certificate the client is trying to replace.
            var original = await db.CertificateRequests
                .AsNoTracking()
                .Where(r => r.SerialNumber == presentedSerial)
                .OrderByDescending(r => r.CreatedAtUtc)
                .FirstOrDefaultAsync(ct);

            var certRequest = new CertificateRequest
            {
                CommonName = commonName,
                RequestedBy = reenrollIdentity,
                RequestedBySubject = reenrollIdentity,
                RenewedFromId = original?.Id,
                Type = EstCertificateType(settings),
                PropertiesJson = System.Text.Json.JsonSerializer.Serialize(new { dnsNames }),
                Status = settings.EstAutoApprove ? CertificateRequestStatus.Approved : CertificateRequestStatus.Pending,
                KeyAlgorithm = detectedCsrAlgorithm,
                CsrPem = csrBase64
            };

            CertificateRequest created;
            try
            {
                created = await certRequests.CreateAsync(certRequest, reenrollIdentity, nameof(CaSettings.EstAutoApprove), ct);
            }
            catch (Policies.IssuancePolicyViolationException ex)
            {
                return await RefuseAsync(Results.BadRequest(new { error = ex.Message, violations = ex.Decision.Violations }),
                    DiagnosticCategories.PolicyRejected, ex.Message);
            }
            catch (PqcPolicyViolationException ex)
            {
                return await RefuseAsync(Results.BadRequest(new { error = ex.Message }), DiagnosticCategories.KeyRefused, ex.Message);
            }
            catch (CaNotInitializedException ex)
            {
                // Nothing can be signed before the CA exists. 503 tells the device this is a server
                // state it may retry, unlike the 400s above which are the client's to fix.
                return await RefuseAsync(Results.Problem(ex.Message, statusCode: 503), DiagnosticCategories.CaNotReady, ex.Message);
            }
            catch (DuplicateRequestException)
            {
                var duplicate = $"An active certificate request already exists for '{commonName}'.";
                return await RefuseAsync(Results.Conflict(new { error = duplicate }), DiagnosticCategories.DuplicateCommonName, duplicate);
            }

            if (settings.EstAutoApprove)
                approvalQueue.TrySignal();

            return await RespondForRequestStatusAsync(created, ct);
        })
        .CountEnrollments(EstEnrollmentMetricsFilter.Reenroll)
        .RequireRateLimiting(EstRateLimiting.PolicyName);

        return endpoints;
    }

    /// <summary>
    /// Detects the CSR's key algorithm. The PQC stage is judged later, inside
    /// <c>CreateAsync</c>, which alone knows whether the row is a renewal (<c>RenewedFromId</c>)
    /// that stage Pilot still allows; a refusal surfaces there as <see cref="PqcPolicyViolationException"/>.
    /// Detection always runs: the returned algorithm is persisted as the request's
    /// <c>KeyAlgorithm</c> and selects the issuing strategy, so falling back to RSA stamped
    /// keyEncipherment/dataEncipherment onto ML-DSA certificates — bits RFC 9881 §5 forbids on a
    /// signature-only key. Returns a non-null error result when the CSR is unparsable or carries an
    /// unsupported key type.
    /// </summary>
    private static (IResult? Error, CertificateKeyAlgorithm Algorithm) DetectCsrAlgorithm(string csrBase64)
    {
        CertificateKeyAlgorithm detected;
        try
        {
            detected = CertificateGenerator.DetectAlgorithmFromCsr(csrBase64);
        }
        catch (NotSupportedException ex)
        {
            return (Results.BadRequest(new { error = ex.Message }), default);
        }
        catch (Exception)
        {
            return (Results.BadRequest(new { error = "The CSR could not be parsed." }), default);
        }

        return (null, detected);
    }

    /// <summary>
    /// True when re-enrollment would have to verify a composite ML-DSA signature: the presented
    /// certificate holds a composite key, was signed with one, or the CA's own key is composite.
    /// </summary>
    internal static bool InvolvesCompositeSignature(X509Certificate2 clientCertificate, X509Certificate2 caCertificate) =>
        Crypto.QertumKeyCodec.IsCompositeOid(clientCertificate.PublicKey.Oid.Value)
        || Crypto.QertumKeyCodec.IsCompositeOid(clientCertificate.SignatureAlgorithm.Value)
        || Crypto.QertumKeyCodec.IsCompositeOid(caCertificate.PublicKey.Oid.Value);

    /// <summary>
    /// Verifies an EST reenrollment's mTLS proof: the presented certificate must chain to this
    /// CA's root and must not be Revoked. Reuses <see cref="ICertificateRequestService.GetRevocationStatusesAsync"/>
    /// — no new revocation check invented.
    /// </summary>
    internal static Task<bool> VerifyReenrollCertificateAsync(
        X509Certificate2 clientCertificate,
        X509Certificate2 caCertificate,
        ICertificateRequestService certRequests,
        CancellationToken ct) =>
        VerifyReenrollCertificateAsync(clientCertificate, [caCertificate], [], certRequests, ct);

    internal static async Task<bool> VerifyReenrollCertificateAsync(
        X509Certificate2 clientCertificate,
        IReadOnlyList<X509Certificate2> anchors,
        IReadOnlyList<X509Certificate2> intermediates,
        ICertificateRequestService certRequests,
        CancellationToken ct)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // revocation checked via GetRevocationStatusesAsync below
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        foreach (var anchor in anchors) chain.ChainPolicy.CustomTrustStore.Add(anchor);
        foreach (var intermediate in intermediates) chain.ChainPolicy.ExtraStore.Add(intermediate);

        if (!chain.Build(clientCertificate)) return false;

        var serial = NormalizeSerial(clientCertificate.SerialNumber);
        var statuses = await certRequests.GetRevocationStatusesAsync([serial], ct);
        if (!statuses.TryGetValue(serial, out var status)) return true; // unknown to us but chains: accept
        return status.State != OcspCertificateState.Revoked;
    }

    /// <summary>
    /// RFC 7030 §4.2.2's mTLS proof only establishes that the presented certificate is one this CA
    /// issued and hasn't revoked — it says nothing about the CSR being renewed. Without this check,
    /// any certificate ever issued could be presented to reenroll a CSR for a completely unrelated
    /// name. The CSR CN must match the certificate CN and each requested DNS SAN must already be
    /// named by the certificate, either as its CN or a DNS SAN.
    /// </summary>
    internal static bool CsrIdentityMatchesCertificate(
        string csrCommonName,
        IReadOnlyList<string> csrDnsNames,
        X509Certificate2 clientCertificate)
    {
        var certificateCommonName = clientCertificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        if (!string.Equals(NormalizeDnsName(csrCommonName), NormalizeDnsName(certificateCommonName), StringComparison.OrdinalIgnoreCase))
            return false;

        var allowedDnsNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { NormalizeDnsName(certificateCommonName) };
        var sanExtension = clientCertificate.Extensions["2.5.29.17"];
        if (sanExtension is not null)
        {
            try
            {
                allowedDnsNames.UnionWith(GeneralNames.GetInstance(sanExtension.RawData).GetNames()
                    .Where(name => name.TagNo == GeneralName.DnsName)
                    .Select(name => NormalizeDnsName(name.Name.ToString()!)));
            }
            catch (Exception)
            {
                return false;
            }
        }

        return csrDnsNames.All(name => allowedDnsNames.Contains(NormalizeDnsName(name)));
    }

    private static string NormalizeDnsName(string name) =>
        name.EndsWith(".", StringComparison.Ordinal) ? name[..^1] : name;

    /// <summary>
    /// <see cref="X509Certificate2.SerialNumber"/> is the DER byte encoding as hex — always an even
    /// number of digits, and padded with a leading "00" byte when the high bit of the value would
    /// otherwise read as negative. <c>MarkAsIssuedAsync</c> stores <c>BigInteger.ToString(16)</c>'s
    /// numeric-value form instead, which carries no such padding. Round-tripping through BouncyCastle's
    /// <see cref="Org.BouncyCastle.Math.BigInteger"/> normalizes both to the same string so the
    /// dictionary lookup in <see cref="VerifyReenrollCertificateAsync"/> matches.
    /// </summary>
    internal static string NormalizeSerial(string serialHex) =>
        new Org.BouncyCastle.Math.BigInteger(serialHex, 16).ToString(16).ToUpperInvariant();

    private static async Task<(IResult? Error, Guid? CredentialId)> TryAuthenticateBasicAsync(
        HttpContext ctx, IEstEnrollmentCredentialService credentials, CancellationToken ct)
    {
        var header = ctx.Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            return (Unauthorized(ctx), null);

        string decoded;
        try
        {
            decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(header["Basic ".Length..]));
        }
        catch (FormatException)
        {
            return (Unauthorized(ctx), null);
        }

        var separatorIndex = decoded.IndexOf(':');
        if (separatorIndex < 0) return (Unauthorized(ctx), null);

        var username = decoded[..separatorIndex];
        var password = decoded[(separatorIndex + 1)..];

        // The credential id, not the username, is the stable identity requests are attributed to:
        // an operator could rename or reissue a username under a different credential later.
        var check = await credentials.CheckAsync(username, password, ct);
        if (check.Outcome == EstCredentialOutcome.Success)
            return (null, check.CredentialId);

        // The device gets the same 401 whatever the reason. Only a refusal against a real credential
        // is recorded: what an unknown client typed as a username could be anything, a password
        // included, so it goes to the operational log without the value.
        if (check.CredentialId is { } credentialId)
        {
            ctx.RequestServices.GetRequiredService<IDiagnosticEventLog>().Record(
                LifecycleSubjectTypes.EstCredential, credentialId, DiagnosticActions.AuthRefused, $"est:{credentialId}",
                check.Outcome == EstCredentialOutcome.Disabled ? DiagnosticCategories.Disabled : DiagnosticCategories.WrongSecret,
                check.Outcome == EstCredentialOutcome.Disabled
                    ? "Authentication refused: the credential is disabled."
                    : "Authentication refused: wrong password.");
        }
        else
        {
            ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Qertum.Services.Est.EstEndpoints")
                .LogInformation("EST authentication refused for a username that matches no credential.");
        }

        return (Unauthorized(ctx), null);
    }

    /// <summary>The default issuer's chain up to and including its root (RFC 7030 §4.1.3: the current CA certificates). Caller disposes.</summary>
    internal static async Task<IReadOnlyList<X509Certificate2>> CaCertificatesAsync(IIssuerRegistry issuers, CancellationToken ct)
    {
        var handle = await issuers.GetDefaultAsync(ct);
        IReadOnlyList<string> chain = handle is null ? [] : await issuers.ChainForAsync(handle.Issuer.Id, ct);
        return [.. chain.Select(p => X509Certificate2.CreateFromPem(p))];
    }

    /// <summary>Roots of every Active/Retired issuer path (trust anchors) and every CA below them. Caller disposes (see <see cref="TrustSet"/>).</summary>
    internal static async Task<(List<X509Certificate2> Anchors, List<X509Certificate2> Intermediates)> TrustSetAsync(IIssuerRegistry issuers, CancellationToken ct)
    {
        var anchorPems = new HashSet<string>(StringComparer.Ordinal);
        var intermediatePems = new HashSet<string>(StringComparer.Ordinal);
        var rows = await issuers.GetAllAsync(ct);
        IEnumerable<IssuerId> ids = rows.Count == 0
            ? (await issuers.GetDefaultAsync(ct)) is { } synthetic ? [synthetic.Issuer.Id] : []
            : rows.Where(i => i.Status is IssuerStatus.Active or IssuerStatus.Retired).Select(i => i.Id);
        foreach (var id in ids)
        {
            var chain = await issuers.ChainForAsync(id, ct);
            if (chain.Count == 0) continue;
            anchorPems.Add(chain[^1].Trim());
            foreach (var pem in chain.Take(chain.Count - 1)) intermediatePems.Add(pem.Trim());
        }
        return ([.. anchorPems.Select(p => X509Certificate2.CreateFromPem(p))], [.. intermediatePems.Select(p => X509Certificate2.CreateFromPem(p))]);
    }

    /// <summary>Disposes the certificates of a <see cref="TrustSetAsync"/> result.</summary>
    private sealed class TrustSet(List<X509Certificate2> anchors, List<X509Certificate2> intermediates) : IDisposable
    {
        public void Dispose()
        {
            foreach (var c in anchors.Concat(intermediates)) c.Dispose();
        }
    }

    private static IResult Unauthorized(HttpContext ctx)
    {
        ctx.Response.Headers.WWWAuthenticate = "Basic realm=\"EST\"";
        return Results.StatusCode(StatusCodes.Status401Unauthorized);
    }

    private static Task<IResult> RespondForRequestStatusAsync(CertificateRequest request, CancellationToken ct)
    {
        if (request.Status == CertificateRequestStatus.Issued && !string.IsNullOrEmpty(request.CertificatePem))
        {
            using var cert = X509Certificate2.CreateFromPem(request.CertificatePem);
            var base64 = EstCmsHelper.BuildDegenerateCmsBase64([cert]);
            return Task.FromResult(Results.Text(base64, Pkcs7MimeType));
        }

        // Not yet issued: RFC 7030 §4.2.3 asynchronous enrollment. The client is expected to
        // resubmit the identical request after the interval.
        return Task.FromResult<IResult>(new RetryAfterResult(TimeSpan.FromSeconds(60)));
    }
}

/// <summary>Minimal <see cref="IResult"/> that writes a 202 with a Retry-After header and empty body.</summary>
file sealed class RetryAfterResult(TimeSpan retryAfter) : IResult, IStatusCodeHttpResult
{
    public int? StatusCode => StatusCodes.Status202Accepted;

    public Task ExecuteAsync(HttpContext httpContext)
    {
        httpContext.Response.StatusCode = StatusCodes.Status202Accepted;
        httpContext.Response.Headers.RetryAfter = ((int)retryAfter.TotalSeconds).ToString();
        return Task.CompletedTask;
    }
}
