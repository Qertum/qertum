using Qertum.Services.Issuers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Qertum.Services.Crypto;
using Qertum.Services.Lifecycle;

namespace Qertum.Services.Acme;

public static class AcmeEndpointMappings
{
    /// <summary>Log category for faults <c>HandleAcme</c> turns into a serverInternal problem.</summary>
    public const string LogCategory = "Qertum.Services.Acme.AcmeEndpoints";

    private const string AcmePemChainType = "application/pem-certificate-chain";

    /// <summary>
    /// Template (and so issuance policy) an ACME request is filed under: whatever
    /// <see cref="CaSettings.AcmeTemplateTypeKey"/> names, falling back to <c>"WebServer"</c> for a
    /// settings row written before the key existed.
    /// </summary>
    private static string AcmeCertificateType(CaSettings settings) =>
        string.IsNullOrWhiteSpace(settings.AcmeTemplateTypeKey) ? "WebServer" : settings.AcmeTemplateTypeKey;

    /// <summary>
    /// Upper bound on identifiers in one order. Each identifier produces an authorization whose
    /// challenge causes an outbound HTTP request, so an uncapped list is an amplification primitive.
    /// </summary>
    private const int MaxIdentifiersPerOrder = 100;

    /// <summary>
    /// Accepts a plain DNS hostname, optionally with a leftmost wildcard label
    /// (<c>*.example.com</c>). <see cref="Uri.CheckHostName"/> does most of the work: it rejects IP
    /// literals, embedded ':' '/' '#', and empty values. A '*' anywhere other than the leftmost
    /// label is rejected — RFC 8555 §7.1.3 allows a wildcard only there, and only dns-01 can
    /// validate one.
    /// </summary>
    public static bool IsValidDnsIdentifier(string? value, out string reason)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            reason = "Identifier value must not be empty.";
            return false;
        }

        if (value.Length > 253)
        {
            reason = $"Identifier '{value}' exceeds the maximum DNS name length.";
            return false;
        }

        TryParseWildcard(value, out var candidate);

        // Only the leftmost label may be a wildcard, and TryParseWildcard has already removed it.
        // Anything still holding a '*' is malformed: "*", "*.", "*.*.com", "a.*.com", "*example.com".
        if (candidate.Contains('*', StringComparison.Ordinal))
        {
            reason = $"Identifier '{value}' may only use a wildcard as its leftmost label.";
            return false;
        }

        if (Uri.CheckHostName(candidate) != UriHostNameType.Dns)
        {
            reason = $"Identifier '{value}' is not a valid DNS name.";
            return false;
        }

        reason = string.Empty;
        return true;
    }

    /// <summary>
    /// Splits a wildcard identifier into its base name. RFC 8555 §7.1.4: the authorization for
    /// <c>*.example.com</c> carries the identifier <c>example.com</c> plus <c>wildcard: true</c>,
    /// and the dns-01 query name is built from the base name — a '*' is never part of a DNS query.
    /// </summary>
    public static bool TryParseWildcard(string value, out string baseName)
    {
        if (value.StartsWith("*.", StringComparison.Ordinal))
        {
            baseName = value[2..];
            return true;
        }

        baseName = value;
        return false;
    }

    /// <summary>
    /// True when one of the account's valid authorizations covers this certificate DNS name.
    /// A wildcard name "*.example.com" is proved by the authorization for "example.com" carrying
    /// Wildcard = true — the authorization stores the base name, so a plain string comparison
    /// against the certificate's name would never match and would refuse a revocation the account
    /// is entitled to. The two forms do not substitute for each other in either direction: a
    /// wildcard authorization does not prove the base name, and a plain one does not prove the
    /// wildcard.
    /// </summary>
    public static bool IsCoveredByAuthorizations(
        string dnsName,
        IReadOnlyCollection<(string Identifier, bool Wildcard)> authorizations)
    {
        var isWildcard = TryParseWildcard(dnsName, out var baseName);

        return authorizations.Any(auth =>
            auth.Wildcard == isWildcard &&
            string.Equals(auth.Identifier, baseName, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Page size for the account orders list. RFC 8555 §7.1.2.1 allows the server to paginate with a
    /// Link rel="next" header; an unbounded list would grow with every order the account ever placed.
    /// </summary>
    private const int AccountOrdersPageSize = 100;

    /// <summary>
    /// Validates the <c>contact</c> array of a new-account or account-update request (RFC 8555 §7.3).
    /// Only <c>mailto:</c> is supported, and a mailto must carry exactly one addr-spec and no hfields
    /// — "mailto:a@b?subject=x" and "mailto:a@b,c@d" are both explicitly forbidden by §7.3.
    /// </summary>
    /// <exception cref="AcmeException">
    /// <c>unsupportedContact</c> for a scheme this server does not accept, <c>invalidContact</c> for a
    /// mailto it cannot use. The two are distinct in the RFC because they tell the client different
    /// things: try another channel, versus fix this address.
    /// </exception>
    private static void ValidateContacts(JsonElement contacts)
    {
        if (contacts.ValueKind == JsonValueKind.Null) return;

        if (contacts.ValueKind != JsonValueKind.Array)
            throw new AcmeException("malformed", "contact must be an array of URIs.");

        foreach (var entry in contacts.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.String || entry.GetString() is not { Length: > 0 } contact)
                throw new AcmeException("invalidContact", "Each contact must be a non-empty URI string.");

            if (!contact.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
                throw new AcmeException("unsupportedContact",
                    $"Contact '{contact}' is not supported: only mailto: addresses are accepted.");

            var address = contact["mailto:".Length..];

            if (address.Contains('?', StringComparison.Ordinal))
                throw new AcmeException("invalidContact",
                    $"Contact '{contact}' carries mailto hfields, which RFC 8555 §7.3 forbids.");

            if (address.Contains(',', StringComparison.Ordinal))
                throw new AcmeException("invalidContact",
                    $"Contact '{contact}' names more than one address; use one entry per address.");

            // MailAddress is strict enough to reject the bare-word and missing-domain cases, and it is
            // the same parser the rest of the framework would use to actually send to the address.
            if (!System.Net.Mail.MailAddress.TryCreate(address, out _))
                throw new AcmeException("invalidContact", $"Contact '{contact}' is not a valid email address.");
        }
    }

    /// <summary>
    /// Returns the raw JSON for a validated <c>contact</c> field, or null when the field is absent.
    /// An explicit empty array is kept as-is: RFC 8555 §7.3.2 makes that the way a client clears its
    /// contacts, which is different from not mentioning the field at all.
    /// </summary>
    private static string? ValidatedContactsJson(JsonElement payload)
    {
        if (!payload.TryGetProperty("contact", out var contacts)) return null;

        ValidateContacts(contacts);
        return contacts.ValueKind == JsonValueKind.Null ? null : contacts.GetRawText();
    }

    public static void MapAcmeEndpoints(this IEndpointRouteBuilder app, string baseUrl)
    {
        // The directory and nonce endpoints, plus every status poll, sit under the polling allowance;
        // anything that creates or changes state goes under the tighter one. Splitting the group is
        // what keeps a client polling an order from spending the budget for issuing certificates.
        var acme = app.MapGroup("/acme").RequireRateLimiting(AcmeRateLimiting.PollingPolicy);
        var acmeWrite = app.MapGroup("/acme").RequireRateLimiting(AcmeRateLimiting.WritePolicy);

        // ── Directory ──────────────────────────────────────────────────────────
        acme.MapGet("/directory", async (
            IAcmeNonceService nonceService,
            CertificateRequestDbContext db,
            HttpResponse response,
            CancellationToken ct) =>
        {
            response.Headers["Replay-Nonce"] = nonceService.GenerateNonce();

            // Read-only: the directory is public and unauthenticated, so it must not be the thing that
            // creates a settings row.
            var requireEab = await db.Settings
                .AsNoTracking()
                .Where(setting => setting.Id == 1)
                .Select(setting => setting.AcmeRequireExternalAccountBinding)
                .FirstOrDefaultAsync(ct);

            return Results.Ok(new
            {
                newNonce = $"{baseUrl}/acme/new-nonce",
                newAccount = $"{baseUrl}/acme/new-account",
                newOrder = $"{baseUrl}/acme/new-order",
                revokeCert = $"{baseUrl}/acme/revoke-cert",
                keyChange = $"{baseUrl}/acme/key-change",
                // RFC 9773: where a client asks when to renew.
                renewalInfo = $"{baseUrl}/acme/renewal-info",
                // §7.1.1: a client that learns binding is required up front can fail with a useful
                // message instead of a rejected registration. Built as a dictionary so the field is
                // absent when binding is optional rather than present and null — a client reading
                // "externalAccountRequired": null should never have to decide what that means.
                meta = requireEab
                    ? new Dictionary<string, object> { ["website"] = baseUrl, ["externalAccountRequired"] = true }
                    : new Dictionary<string, object> { ["website"] = baseUrl }
            });
        });

        // ── Renewal information (RFC 9773) ────────────────────────────────────
        // Unauthenticated GET, no nonce. The identifier is public (authority key id + serial), so the answer carries
        // nothing the certificate itself does not: a window, never a subject. The key id must match the stored
        // certificate's, so a serial alone does not find anything.
        acme.MapGet("/renewal-info/{certId}", async (
            string certId,
            CertificateRequestDbContext db,
            TimeProvider clock,
            HttpResponse response,
            CancellationToken ct) =>
        {
            if (!AcmeRenewalInfo.TryParseCertId(certId, out var authorityKeyId, out var serialHex))
                return AcmeProblem("malformed", "The certificate identifier is not valid.");

            var cert = await db.CertificateRequests.AsNoTracking()
                .Where(r => r.SerialNumber == serialHex && r.CertificatePem != null)
                .Select(r => new { r.Status, r.ValidFrom, r.ValidTo, r.CertificatePem, r.IssuerId })
                .FirstOrDefaultAsync(ct);
            if (cert is null || cert.ValidFrom is not { } validFrom || cert.ValidTo is not { } validTo
                || cert.Status is not (CertificateRequestStatus.Issued or CertificateRequestStatus.PendingRevocation
                    or CertificateRequestStatus.Revoked))
                return Results.NotFound();

            var stored = QertumKeyCodec.ReadCertificatePem(cert.CertificatePem!);
            var storedKeyId = stored is null ? null : AcmeRenewalInfo.AuthorityKeyIdOf(stored);
            if (storedKeyId is null || !storedKeyId.AsSpan().SequenceEqual(authorityKeyId))
                return Results.NotFound();

            // A retired issuer issues nothing new: renewing moves the certificate to the current one.
            var issuerRetired = cert.IssuerId is { } issuerId && await db.Issuers.AsNoTracking()
                .AnyAsync(i => i.Id == issuerId && (i.Status == IssuerStatus.Retired || i.Status == IssuerStatus.Archived), ct);
            var settings = await db.Settings.AsNoTracking().Where(setting => setting.Id == 1).FirstOrDefaultAsync(ct)
                ?? new CaSettings();

            var (start, end) = AcmeRenewalInfo.SuggestedWindow(
                validFrom, validTo,
                renewNow: issuerRetired || cert.Status != CertificateRequestStatus.Issued,
                renewDaysBeforeExpiry: settings.AutoRenewalDaysBeforeExpiry ?? settings.ExpiringSoonDays,
                nowUtc: clock.GetUtcNow().UtcDateTime);

            response.Headers["Retry-After"] = AcmeRenewalInfo.RetryAfterSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
            return Results.Ok(new
            {
                suggestedWindow = new
                {
                    start = start.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture),
                    end = end.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture)
                }
            });
        });

        // ── Nonce ─────────────────────────────────────────────────────────────
        acme.MapMethods("/new-nonce", ["HEAD", "GET"], (IAcmeNonceService nonceService, HttpResponse response) =>
        {
            response.Headers["Replay-Nonce"] = nonceService.GenerateNonce();
            response.Headers.CacheControl = "no-store";
            return Results.Ok();
        });

        // ── New Account ───────────────────────────────────────────────────────
        acmeWrite.MapPost("/new-account", async (
            HttpContext ctx,
            JwsRequestParser parser,
            CertificateRequestDbContext db,
            IAcmeNonceService nonceService,
            TimeProvider clock,
            CancellationToken ct) =>
        {
            return await HandleAcme(ctx, nonceService, async () =>
            {
                var jws = await parser.ParseAsync(ctx.Request, ct);
                if (jws.EmbeddedJwk is null)
                    return AcmeProblem("malformed", "new-account requires a JWK in the protected header.");

                var payload = jws.Payload?.RootElement
                    ?? throw new AcmeException("malformed", "Missing payload.");

                var existing = await db.AcmeAccounts
                    .FirstOrDefaultAsync(a => a.JwkThumbprint == jws.JwkThumbprint, ct);

                if (existing is not null)
                {
                    ctx.Response.Headers.Location = $"{baseUrl}/acme/account/{existing.Id}";
                    return Results.Ok(MapAccount(existing, baseUrl));
                }

                // onlyReturnExisting check
                if (AcmeJson.OptionalBool(payload, "onlyReturnExisting", "payload"))
                    return AcmeProblem("accountDoesNotExist", "No account found for this key.");

                // External account binding (RFC 8555 §7.3.4). Checked only for registrations that
                // would create an account: an existing account already passed this gate.
                var settings = await db.Settings.AsNoTracking().FirstOrDefaultAsync(setting => setting.Id == 1, ct);
                AcmeExternalAccountKey? boundCredential = null;
                var hasBinding = payload.TryGetProperty("externalAccountBinding", out var bindingEl);

                if (settings?.AcmeRequireExternalAccountBinding == true && !hasBinding)
                    return Results.Problem(
                        title: "externalAccountRequired",
                        detail: "This server requires an external account binding to create an account.",
                        statusCode: StatusCodes.Status403Forbidden,
                        type: "urn:ietf:params:acme:error:externalAccountRequired");

                if (hasBinding)
                {
                    // Verified even when not required: a client that sends a binding is asserting one,
                    // and accepting an invalid assertion would record a credential that never checked out.
                    boundCredential = await AcmeExternalAccountBinding.VerifyAsync(
                        bindingEl, jws.EmbeddedJwk, $"{baseUrl}/acme/new-account", db, ct);

                    // One credential, one account. Otherwise a single leaked key mints accounts forever.
                    if (boundCredential.BoundAccountId is not null)
                        return AcmeProblem("unauthorized", "This external account key is already bound to an account.");
                }

                var account = new AcmeAccount
                {
                    JwkThumbprint = jws.JwkThumbprint,
                    PublicKeyJwk = jws.EmbeddedJwk,
                    ExternalAccountKid = boundCredential?.Kid,
                    TermsOfServiceAgreed = AcmeJson.OptionalBool(payload, "termsOfServiceAgreed", "payload"),
                    ContactsJson = ValidatedContactsJson(payload)
                };
                db.AcmeAccounts.Add(account);

                if (boundCredential is not null)
                {
                    // Tracked instance, not the AsNoTracking read above, so the binding is saved in the
                    // same transaction as the account it belongs to.
                    var tracked = await db.AcmeExternalAccountKeys.FirstAsync(k => k.Id == boundCredential.Id, ct);
                    tracked.BoundAccountId = account.Id;
                    tracked.BoundAtUtc = clock.GetUtcNow().UtcDateTime;
                }

                await db.SaveChangesAsync(ct);

                ctx.Response.Headers.Location = $"{baseUrl}/acme/account/{account.Id}";
                return Results.Created($"{baseUrl}/acme/account/{account.Id}", MapAccount(account, baseUrl));
            });
        });

        // ── Account (POST-as-GET and update) ──────────────────────────────────
        // Deliberately on the polling allowance rather than the write one: clients fetch their own
        // account on nearly every run, while updates are rare, so metering this as a write would
        // charge ordinary startup traffic against the issuance budget.
        acme.MapPost("/account/{id:guid}", async (
            Guid id,
            HttpContext ctx,
            JwsRequestParser parser,
            IAcmeNonceService nonceService,
            CertificateRequestDbContext db,
            TimeProvider clock,
            CancellationToken ct) =>
        {
            return await HandleAcme(ctx, nonceService, async () =>
            {
                // Every kid points here and new-account hands this URL back in Location, so a client
                // fetching its own account had been getting a 404 from a URL the server told it to use.
                var jws = await parser.ParseAsync(ctx.Request, ct);
                var account = jws.Account ?? throw new AcmeException("unauthorized", "Account required.");

                // The parser resolved the account from the kid and verified the signature against that
                // account's key, so an account can only ever read itself; a mismatched id is someone
                // asking about an account they did not authenticate as.
                if (account.Id != id)
                    return AcmeProblem("unauthorized", "The signing account does not match the requested account.");

                // An empty payload is POST-as-GET; anything else is an update (RFC 8555 §7.3.2).
                var payload = jws.Payload?.RootElement;
                if (payload is null)
                    return Results.Ok(MapAccount(account, baseUrl));

                var update = payload.Value;

                if (update.TryGetProperty("status", out _))
                {
                    var requested = AcmeJson.OptionalString(update, "status", "payload");

                    // §7.3.6 gives the client exactly one status it may set. "revoked" is the server's
                    // to assign, and "valid" would let a holder undo the only kill switch they have.
                    if (requested != "deactivated")
                        return AcmeProblem("malformed",
                            $"Only \"deactivated\" may be requested for an account status, not \"{requested}\".");

                    account.Status = "deactivated";
                }

                if (update.TryGetProperty("contact", out var contactEl))
                {
                    ValidateContacts(contactEl);
                    account.ContactsJson = contactEl.ValueKind == JsonValueKind.Null ? null : contactEl.GetRawText();
                }

                account.UpdatedAtUtc = clock.GetUtcNow().UtcDateTime;
                await db.SaveChangesAsync(ct);

                return Results.Ok(MapAccount(account, baseUrl));
            });
        });

        // ── Account orders (POST-as-GET) ──────────────────────────────────────
        acme.MapPost("/account/{id:guid}/orders", async (
            Guid id,
            HttpContext ctx,
            JwsRequestParser parser,
            IAcmeNonceService nonceService,
            CertificateRequestDbContext db,
            int? cursor,
            CancellationToken ct) =>
        {
            return await HandleAcme(ctx, nonceService, async () =>
            {
                var jws = await parser.ParseAsync(ctx.Request, ct);
                var account = jws.Account ?? throw new AcmeException("unauthorized", "Account required.");

                if (account.Id != id)
                    return AcmeProblem("unauthorized", "The signing account does not match the requested account.");

                // Paged, with one extra row read to decide whether a next link is warranted, so the
                // response cannot grow without bound as an account accumulates orders.
                var skip = Math.Max(0, cursor ?? 0);
                var page = await db.AcmeOrders
                    .AsNoTracking()
                    .Where(order => order.AccountId == account.Id)
                    .OrderByDescending(order => order.CreatedAtUtc)
                    .ThenBy(order => order.Id)
                    .Skip(skip)
                    .Take(AccountOrdersPageSize + 1)
                    .Select(order => order.Id)
                    .ToListAsync(ct);

                var hasMore = page.Count > AccountOrdersPageSize;
                var ids = hasMore ? page.Take(AccountOrdersPageSize) : page;

                if (hasMore)
                    ctx.Response.Headers.Link =
                        $"<{baseUrl}/acme/account/{account.Id}/orders?cursor={skip + AccountOrdersPageSize}>;rel=\"next\"";

                return Results.Ok(new { orders = ids.Select(orderId => $"{baseUrl}/acme/order/{orderId}").ToArray() });
            });
        });

        // ── New Order ─────────────────────────────────────────────────────────
        acmeWrite.MapPost("/new-order", async (
            HttpContext ctx,
            JwsRequestParser parser,
            CertificateRequestDbContext db,
            IOptions<AcmeDns01Options> dns01Options,
            ICertificateRequestService certReqService,
            Policies.IIssuancePolicyService issuancePolicy,
            IAcmeNonceService nonceService,
            IDiagnosticEventLog diagnostics,
            ProtocolMetrics metrics,
            TimeProvider clock,
            CancellationToken ct) =>
        {
            return await HandleAcme(ctx, nonceService, async () =>
            {
                var jws = await parser.ParseAsync(ctx.Request, ct);
                var account = jws.Account ?? throw new AcmeException("unauthorized", "Account required.");

                var performedBy = $"acme:{account.Id}";
                // No order exists yet, so a refusal is recorded against the account.
                IResult Refuse(string errorType, string category, string detail)
                {
                    diagnostics.Record(LifecycleSubjectTypes.AcmeAccount, account.Id, DiagnosticActions.NewOrderRefused,
                        performedBy, category, detail);
                    return AcmeProblem(errorType, detail);
                }

                var payload = jws.Payload?.RootElement
                    ?? throw new AcmeException("malformed", "POST-as-GET not valid for new-order.");

                var identifiers = AcmeJson.RequiredArray(payload, "identifiers", "payload").EnumerateArray()
                    .Select(i => (Type: AcmeJson.RequiredString(i, "type", "identifier"),
                                  Value: AcmeJson.RequiredString(i, "value", "identifier")))
                    .ToList();

                if (identifiers.Count == 0)
                    return Refuse("malformed", DiagnosticCategories.NoIdentifiers, "At least one identifier is required.");
                if (identifiers.Count > MaxIdentifiersPerOrder)
                    return Refuse("malformed", DiagnosticCategories.TooManyIdentifiers,
                        $"An order may contain at most {MaxIdentifiersPerOrder} identifiers.");
                if (identifiers.Any(i => i.Type != "dns"))
                    return Refuse("unsupportedIdentifier", DiagnosticCategories.UnsupportedIdentifierType, "Only 'dns' identifiers are supported.");

                // Reject anything that is not a plain DNS name before an order row exists. This alone
                // does not stop a name that resolves to an internal address — the address policy in the
                // challenge verifier does that — but it keeps IP literals, embedded delimiters and
                // malformed wildcards out of the system entirely.
                var dns01Enabled = dns01Options.Value.Enabled;
                foreach (var (_, value) in identifiers)
                {
                    if (!IsValidDnsIdentifier(value, out var reason))
                        return Refuse("malformed", DiagnosticCategories.InvalidIdentifier, reason);

                    // Only dns-01 can validate a wildcard, so with dns-01 off the order could never
                    // reach "ready". Refusing here beats handing back an order that hangs forever.
                    if (!dns01Enabled && TryParseWildcard(value, out _))
                        return Refuse("malformed", DiagnosticCategories.WildcardNeedsDns01,
                            $"Wildcard identifier '{value}' requires the dns-01 challenge, which is disabled.");
                }

                // Refuse names the ACME template's policy can never allow before an order row exists,
                // so the client does no challenge work for them. Only name rules apply here: the key
                // algorithm and validity are unknown until finalize, which runs the full evaluation
                // through CreateAsync.
                var policySettings = await certReqService.GetSettingsAsync(ct);
                var probe = new CertificateRequest
                {
                    CommonName = identifiers[0].Value,
                    Type = AcmeCertificateType(policySettings),
                    PropertiesJson = JsonSerializer.Serialize(new { dnsNames = identifiers.Select(i => i.Value).ToList() })
                };
                var probeDecision = await issuancePolicy.EvaluateAsync(probe, policySettings, ct);
                var nameViolations = probeDecision.Violations
                    .Where(v => v.Rule is Policies.PolicyRules.DnsSuffix or Policies.PolicyRules.Template or Policies.PolicyRules.IssuerNameConstraints)
                    .ToList();
                if (nameViolations.Count > 0)
                    return Refuse("rejectedIdentifier", DiagnosticCategories.OutsidePolicy, string.Join("; ", nameViolations.Select(v => v.Message)));

                var order = new AcmeOrder
                {
                    AccountId = account.Id,
                    IdentifiersJson = JsonSerializer.Serialize(identifiers.Select(i => new { type = i.Type, value = i.Value })),
                    ExpiresAtUtc = clock.GetUtcNow().UtcDateTime.AddDays(7)
                };
                db.AcmeOrders.Add(order);

                foreach ((string type, string value) in identifiers)
                {
                    // RFC 8555 §7.1.4: the authorization carries the base name, and the wildcard
                    // travels as a separate flag. The dns-01 query name is built from the base name.
                    var isWildcard = TryParseWildcard(value, out var baseName);

                    var auth = new AcmeAuthorization
                    {
                        OrderId = order.Id,
                        IdentifierType = type,
                        IdentifierValue = baseName,
                        Wildcard = isWildcard,
                        ExpiresAtUtc = clock.GetUtcNow().UtcDateTime.AddDays(7)
                    };
                    db.AcmeAuthorizations.Add(auth);

                    // RFC 8555 §8.4 forbids http-01 for a wildcard: there is no single host to
                    // fetch from. Each challenge gets its own token — AcmeChallenge.Token is
                    // unique-indexed, so the two cannot share one.
                    if (!isWildcard)
                        db.AcmeChallenges.Add(NewChallenge(auth.Id, "http-01"));

                    if (dns01Enabled)
                        db.AcmeChallenges.Add(NewChallenge(auth.Id, "dns-01"));
                }

                await db.SaveChangesAsync(ct);
                metrics.AcmeOrders.Add(1, new KeyValuePair<string, object?>("outcome", "created"));
                diagnostics.Record(LifecycleSubjectTypes.AcmeOrder, order.Id, DiagnosticActions.OrderCreated, performedBy,
                    detail: string.Join(", ", identifiers.Select(i => i.Value)));

                ctx.Response.Headers.Location = $"{baseUrl}/acme/order/{order.Id}";
                return Results.Created(
                    $"{baseUrl}/acme/order/{order.Id}",
                    await BuildOrderResponse(order.Id, db, baseUrl, clock.GetUtcNow().UtcDateTime, ct));
            });
        });

        // ── Authorization (POST-as-GET) ────────────────────────────────────────
        acme.MapPost("/authz/{id:guid}", async (
            Guid id,
            HttpContext ctx,
            JwsRequestParser parser,
            CertificateRequestDbContext db,
            IAcmeNonceService nonceService,
            TimeProvider clock,
            CancellationToken ct) =>
        {
            return await HandleAcme(ctx, nonceService, async () =>
            {
                var jws = await parser.ParseAsync(ctx.Request, ct);
                var account = jws.Account ?? throw new AcmeException("unauthorized", "Account required.");

                var auth = await db.AcmeAuthorizations
                    .Include(a => a.Challenges)
                    .Include(a => a.Order)
                    .FirstOrDefaultAsync(a => a.Id == id && a.Order.AccountId == account.Id, ct);

                return auth is null
                    ? Results.NotFound()
                    : Results.Ok(MapAuthorization(auth, baseUrl, clock.GetUtcNow().UtcDateTime));
            });
        });

        // ── Challenge ─────────────────────────────────────────────────────────
        acmeWrite.MapPost("/challenge/{id:guid}", async (
            Guid id,
            HttpContext ctx,
            JwsRequestParser parser,
            CertificateRequestDbContext db,
            IAcmeNonceService nonceService,
            IDiagnosticEventLog diagnostics,
            TimeProvider clock,
            CancellationToken ct) =>
        {
            return await HandleAcme(ctx, nonceService, async () =>
            {
                var jws = await parser.ParseAsync(ctx.Request, ct);
                var account = jws.Account ?? throw new AcmeException("unauthorized", "Account required.");

                var challenge = await db.AcmeChallenges
                    .Include(c => c.Authorization).ThenInclude(a => a.Order)
                    .FirstOrDefaultAsync(c => c.Id == id && c.Authorization.Order.AccountId == account.Id, ct);

                if (challenge is null) return Results.NotFound();

                // Validating an expired authorization would let a client bank proof of control long
                // after the window in which the server was willing to trust it.
                if (challenge.Authorization.ExpiresAtUtc <= clock.GetUtcNow().UtcDateTime ||
                    challenge.Authorization.Order.ExpiresAtUtc <= clock.GetUtcNow().UtcDateTime)
                {
                    diagnostics.Record(LifecycleSubjectTypes.AcmeOrder, challenge.Authorization.OrderId,
                        DiagnosticActions.ChallengeRefused, $"acme:{account.Id}", DiagnosticCategories.Expired,
                        "Authorization has expired.");
                    return AcmeProblem("malformed", "Authorization has expired.");
                }

                // RFC 8555 §7.5.1: point the client back at the authorization this challenge belongs to.
                ctx.Response.Headers.Link = $"<{baseUrl}/acme/authz/{challenge.AuthorizationId}>;rel=\"up\"";

                if (challenge.Status != "pending")
                    return Results.Ok(MapChallenge(challenge, baseUrl));

                challenge.Status = "processing";
                await db.SaveChangesAsync(ct);
                diagnostics.Record(LifecycleSubjectTypes.AcmeOrder, challenge.Authorization.OrderId,
                    DiagnosticActions.ChallengeTriggered, $"acme:{account.Id}",
                    detail: $"{challenge.Type} for {challenge.Authorization.IdentifierValue}");

                return Results.Ok(MapChallenge(challenge, baseUrl));
            });
        });

        // ── Finalize ──────────────────────────────────────────────────────────
        acmeWrite.MapPost("/finalize/{orderId:guid}", async (
            Guid orderId,
            HttpContext ctx,
            JwsRequestParser parser,
            CertificateRequestDbContext db,
            ICertificateRequestService certReqService,
            ICertificateApprovalQueue approvalQueue,
            IAcmeNonceService nonceService,
            IDiagnosticEventLog diagnostics,
            TimeProvider clock,
            CancellationToken ct) =>
        {
            return await HandleAcme(ctx, nonceService, async () =>
            {
                var jws = await parser.ParseAsync(ctx.Request, ct);
                var account = jws.Account ?? throw new AcmeException("unauthorized", "Account required.");
                var payload = jws.Payload?.RootElement
                    ?? throw new AcmeException("malformed", "POST-as-GET not valid for finalize.");

                var order = await db.AcmeOrders
                    .Include(o => o.Authorizations).ThenInclude(a => a.Challenges)
                    .FirstOrDefaultAsync(o => o.Id == orderId && o.AccountId == account.Id, ct);

                if (order is null) return Results.NotFound();

                var performedBy = $"acme:{account.Id}";
                IResult Refuse(string errorType, string category, string detail)
                {
                    diagnostics.Record(LifecycleSubjectTypes.AcmeOrder, order.Id, DiagnosticActions.FinalizeRefused,
                        performedBy, category, detail);
                    return AcmeProblem(errorType, detail);
                }

                // Domain ownership can change between validation and finalize, which is the whole
                // reason an order carries an expiry. Past it, the proof it holds buys nothing.
                if (order.ExpiresAtUtc <= clock.GetUtcNow().UtcDateTime ||
                    order.Authorizations.Any(a => a.ExpiresAtUtc <= clock.GetUtcNow().UtcDateTime))
                    return Refuse("malformed", DiagnosticCategories.Expired, "Order has expired.");

                if (order.Status != "ready")
                    return Refuse("orderNotReady", DiagnosticCategories.OrderNotReady, "Order is not in 'ready' state.");

                // Only the CSR's public key is used. Its subject and SANs are deliberately ignored —
                // the certificate's identity comes from the order identifiers that were actually
                // validated, which is what stops a client from validating one name and having a
                // certificate issued for another. This is not an oversight; do not "fix" it by
                // reading names out of the CSR.
                var csrB64 = AcmeJson.RequiredString(payload, "csr", "payload");

                order.CsrPem = csrB64;

                // Extract primary domain from identifiers
                // IdentifiersJson is written with lowercase names ("type"/"value"), so this has to
                // read case-insensitively. Matching by exact case silently produced an empty Value
                // for every identifier, which issued certificates with a blank common name.
                var identifiers = JsonSerializer.Deserialize<List<AcmeIdentifier>>(
                        order.IdentifiersJson, IdentifierJsonOptions)
                    ?? throw new AcmeException("serverInternal", "Cannot parse order identifiers.");
                if (identifiers.Any(i => string.IsNullOrWhiteSpace(i.Value)))
                    throw new AcmeException("serverInternal", "Order identifiers are unreadable.");
                var primaryDomain = identifiers.FirstOrDefault()?.Value
                    ?? throw new AcmeException("serverInternal", "Order has no identifiers.");

                var settings = await certReqService.GetSettingsAsync(ct);

                // Always detected, never assumed. The detected value is persisted as KeyAlgorithm
                // below and is what selects the issuing ICertificateAlgorithmStrategy, so defaulting
                // it to RSA made GenerateFromCsr stamp keyEncipherment/dataEncipherment onto an
                // ML-DSA certificate — bits RFC 9881 §5 forbids on a signature-only key. Only the
                // PQC-stage *rejection* is judged later, in CreateAsync; the detection itself never is.
                CertificateKeyAlgorithm detectedCsrAlgorithm;
                try
                {
                    detectedCsrAlgorithm = CertificateGenerator.DetectAlgorithmFromCsr(csrB64);
                }
                catch (NotSupportedException ex)
                {
                    return Refuse("badCSR", DiagnosticCategories.KeyRefused, ex.Message);
                }
                catch (Exception)
                {
                    return Refuse("badCSR", DiagnosticCategories.UnparseableCsr, "The CSR could not be parsed.");
                }

                // An ACME client renews by ordering the same domain again while the certificate it
                // already holds is still active, so a repeat finalize is the normal case, not an
                // error. Point the new request at the one it replaces: that is what the active
                // common-name uniqueness rule exempts, and it is the back-pointer AutoRevokeOnRenewal
                // follows when the request is approved through MarkAsApprovedAsync (the
                // AcmeAutoApprove path inserts an already-Approved row and so never reaches it).
                // Scoped to this account so one account cannot attach its renewal to another's
                // certificate.
                var accountRef = $"acme:{account.Id}";
                var supersedes = await db.CertificateRequests
                    .AsNoTracking()
                    .Where(r => r.CommonName == primaryDomain &&
                                r.RequestedBySubject == accountRef &&
                                r.Status != CertificateRequestStatus.Rejected &&
                                r.Status != CertificateRequestStatus.Revoked)
                    .OrderByDescending(r => r.CreatedAtUtc)
                    .Select(r => r.Id)
                    .FirstOrDefaultAsync(ct);

                var certRequest = new CertificateRequest
                {
                    CommonName = primaryDomain,
                    RequestedBy = accountRef,
                    // ACME requests hold no private key server-side, so this is attribution only —
                    // the key endpoint returns 404 for these rows regardless of caller.
                    RequestedBySubject = accountRef,
                    RenewedFromId = supersedes == default ? null : supersedes,
                    Type = AcmeCertificateType(settings),
                    PropertiesJson = JsonSerializer.Serialize(new
                    {
                        dnsNames = identifiers.Where(i => i.Type == "dns").Select(i => i.Value).ToList()
                    }),
                    Status = settings.AcmeAutoApprove
                        ? CertificateRequestStatus.Approved
                        : CertificateRequestStatus.Pending,
                    KeyAlgorithm = detectedCsrAlgorithm,
                    CsrPem = csrB64
                };

                CertificateRequest created;
                try
                {
                    created = await certReqService.CreateAsync(certRequest, accountRef, nameof(CaSettings.AcmeAutoApprove), ct);
                }
                catch (Policies.IssuancePolicyViolationException ex)
                {
                    // RFC 8555 has no policy error. A name outside policy is a rejected identifier, a
                    // disallowed key is the CSR's to fix, and anything else is simply not authorized.
                    var rules = ex.Decision.Violations.Select(v => v.Rule).ToHashSet();
                    var errorType = rules.All(r => r is Policies.PolicyRules.DnsSuffix or Policies.PolicyRules.IpRange)
                        ? "rejectedIdentifier"
                        : rules.All(r => r == Policies.PolicyRules.KeyAlgorithm)
                            ? "badCSR"
                            : "unauthorized";
                    return Refuse(errorType, DiagnosticCategories.PolicyRejected, ex.Message);
                }
                catch (PqcPolicyViolationException ex)
                {
                    // The PQC stage is judged inside CreateAsync, which alone knows whether this is a
                    // repeat order (RenewedFromId) and so a renewal that Pilot still allows. The CSR's
                    // key is the client's to change.
                    return Refuse("badCSR", DiagnosticCategories.KeyRefused, ex.Message);
                }
                catch (CaNotInitializedException ex)
                {
                    // No CA exists yet, so nothing can be signed. RFC 8555 has no "not configured"
                    // error; serverInternal is the honest one — the condition is the server's, not
                    // the client's, and a client that retries later succeeds once the CA is approved.
                    return Refuse("serverInternal", DiagnosticCategories.CaNotReady, ex.Message);
                }
                catch (DuplicateRequestException)
                {
                    // Another account already holds an active request for this name, or two
                    // finalizes for a first-time name raced. Either way it is a client-visible
                    // condition, not a server fault — do not let it surface as a 500.
                    return Refuse("rateLimited", DiagnosticCategories.DuplicateCommonName,
                        $"An active certificate request already exists for '{primaryDomain}'.");
                }

                order.CertificateRequestId = (Guid)created.Id;
                order.Status = "processing";
                order.UpdatedAtUtc = clock.GetUtcNow().UtcDateTime;
                await db.SaveChangesAsync(ct);
                diagnostics.Record(LifecycleSubjectTypes.AcmeOrder, order.Id, DiagnosticActions.Finalized, performedBy,
                    detail: settings.AcmeAutoApprove
                        ? "Certificate request filed and approved automatically."
                        : "Certificate request filed; awaiting approval.",
                    data: new { certificateRequestId = (Guid)created.Id, autoApproved = settings.AcmeAutoApprove });

                if (settings.AcmeAutoApprove)
                    approvalQueue.TrySignal();

                return Results.Ok(await BuildOrderResponse(order.Id, db, baseUrl, clock.GetUtcNow().UtcDateTime, ct));
            });
        });

        // ── Order (POST-as-GET) ────────────────────────────────────────────────
        acme.MapPost("/order/{id:guid}", async (
            Guid id,
            HttpContext ctx,
            JwsRequestParser parser,
            CertificateRequestDbContext db,
            ICertificateRequestService certReqService,
            IIssuerRegistry issuers,
            IAcmeNonceService nonceService,
            ProtocolMetrics metrics,
            TimeProvider clock,
            CancellationToken ct) =>
        {
            return await HandleAcme(ctx, nonceService, async () =>
            {
                var jws = await parser.ParseAsync(ctx.Request, ct);
                var account = jws.Account ?? throw new AcmeException("unauthorized", "Account required.");

                var order = await db.AcmeOrders
                    .FirstOrDefaultAsync(o => o.Id == id && o.AccountId == account.Id, ct);
                if (order is null) return Results.NotFound();

                // Sync status from the underlying CertificateRequest
                if (order is not { Status: "processing", CertificateRequestId: not null })
                    return Results.Ok(await BuildOrderResponse(order.Id, db, baseUrl, clock.GetUtcNow().UtcDateTime, ct));

                var cr = await certReqService.GetByIdAsync(
                    new CertificateRequestId(order.CertificateRequestId.Value), ct);

                switch (cr?.Status)
                {
                    case CertificateRequestStatus.Issued when cr.CertificatePem is not null:
                        order.Status = "valid";
                        var issuer = await issuers.ForRequestAsync(cr, ct);
                        IReadOnlyList<string> chain = issuer is null ? [] : await issuers.ChainForAsync(issuer.Issuer.Id, ct);
                        order.CertificatePem = BuildChainPem(cr.CertificatePem, chain);
                        order.UpdatedAtUtc = clock.GetUtcNow().UtcDateTime;
                        await db.SaveChangesAsync(ct);
                        metrics.AcmeOrders.Add(1, new KeyValuePair<string, object?>("outcome", "valid"));
                        break;
                    case CertificateRequestStatus.Rejected:
                        order.Status = "invalid";
                        order.UpdatedAtUtc = clock.GetUtcNow().UtcDateTime;
                        await db.SaveChangesAsync(ct);
                        metrics.AcmeOrders.Add(1, new KeyValuePair<string, object?>("outcome", "invalid"));
                        break;
                }

                return Results.Ok(await BuildOrderResponse(order.Id, db, baseUrl, clock.GetUtcNow().UtcDateTime, ct));
            });
        });

        // ── Certificate (POST-as-GET) ─────────────────────────────────────────
        acme.MapPost("/certificate/{id:guid}", async (
            Guid id,
            HttpContext ctx,
            JwsRequestParser parser,
            CertificateRequestDbContext db,
            IAcmeNonceService nonceService,
            CancellationToken ct) =>
        {
            return await HandleAcme(ctx, nonceService, async () =>
            {
                var jws = await parser.ParseAsync(ctx.Request, ct);
                var account = jws.Account ?? throw new AcmeException("unauthorized", "Account required.");

                var order = await db.AcmeOrders
                    .FirstOrDefaultAsync(o => o.Id == id && o.AccountId == account.Id, ct);
                if (order is null) return Results.NotFound();

                // An order that has not been issued yet has no chain to serve. Returning the null
                // body as a 200 hands the client an empty PEM and lets it treat that as success.
                if (order.Status != "valid" || string.IsNullOrEmpty(order.CertificatePem))
                    return Results.NotFound();

                return Results.Content(order.CertificatePem, AcmePemChainType);
            });
        });

        // ── Key Change ────────────────────────────────────────────────────────
        acmeWrite.MapPost("/key-change", async (
            HttpContext ctx,
            JwsRequestParser parser,
            CertificateRequestDbContext db,
            IAcmeNonceService nonceService,
            TimeProvider clock,
            CancellationToken ct) =>
        {
            return await HandleAcme(ctx, nonceService, async () =>
            {
                // RFC 8555 §7.3.5. Two signatures, and both are needed: the outer one proves the
                // holder of the current account key asked for the change, the inner one proves the
                // new key exists and its holder consented. Either alone would let one party move an
                // account onto a key the other does not control.
                var jws = await parser.ParseAsync(ctx.Request, ct);
                var account = jws.Account ?? throw new AcmeException("unauthorized", "Account required.");
                var outerPayload = jws.Payload?.RootElement
                    ?? throw new AcmeException("malformed", "POST-as-GET not valid for key-change.");

                var keyChangeUrl = $"{baseUrl}/acme/key-change";
                var (innerPayloadDoc, newJwkJson, newThumbprint) =
                    JwsRequestParser.ParseInnerJws(outerPayload, keyChangeUrl);

                using (innerPayloadDoc)
                {
                    var innerPayload = innerPayloadDoc.RootElement;

                    // The inner payload names the account being moved. Without this check an inner
                    // JWS captured from one account could be replayed to re-key a different one.
                    var claimedAccount = AcmeJson.OptionalString(innerPayload, "account", "inner payload");
                    var accountUrl = $"{baseUrl}/acme/account/{account.Id}";
                    if (!string.Equals(claimedAccount, accountUrl, StringComparison.OrdinalIgnoreCase))
                        return AcmeProblem("malformed", "Inner payload 'account' does not match the requesting account.");

                    // And it names the key being replaced, so a stale request cannot undo a rotation
                    // that already happened.
                    if (!innerPayload.TryGetProperty("oldKey", out var oldKeyEl))
                        return AcmeProblem("malformed", "Inner payload is missing 'oldKey'.");
                    if (!string.Equals(JwkConverter.ComputeThumbprint(oldKeyEl.ToString()), account.JwkThumbprint, StringComparison.Ordinal))
                        return AcmeProblem("malformed", "Inner payload 'oldKey' is not this account's current key.");

                    if (string.Equals(newThumbprint, account.JwkThumbprint, StringComparison.Ordinal))
                        return AcmeProblem("malformed", "The new key is the same as the current account key.");

                    // §7.3.5: if the new key is already in use, answer 409 and point at the account
                    // that holds it rather than merging the two.
                    var conflicting = await db.AcmeAccounts
                        .FirstOrDefaultAsync(a => a.JwkThumbprint == newThumbprint, ct);
                    if (conflicting is not null)
                    {
                        ctx.Response.Headers.Location = $"{baseUrl}/acme/account/{conflicting.Id}";
                        return Results.Problem(
                            title: "malformed",
                            detail: "The requested key is already in use by another account.",
                            statusCode: StatusCodes.Status409Conflict,
                            type: "urn:ietf:params:acme:error:malformed");
                    }

                    account.JwkThumbprint = newThumbprint;
                    account.PublicKeyJwk = newJwkJson;
                    account.UpdatedAtUtc = clock.GetUtcNow().UtcDateTime;
                    await db.SaveChangesAsync(ct);
                }

                ctx.Response.Headers.Location = $"{baseUrl}/acme/account/{account.Id}";
                return Results.Ok(MapAccount(account, baseUrl));
            });
        });

        // ── Revoke Certificate ────────────────────────────────────────────────
        acmeWrite.MapPost("/revoke-cert", async (
            HttpContext ctx,
            JwsRequestParser parser,
            CertificateRequestDbContext db,
            ICertificateRequestService certReqService,
            ICertificateRevocationQueue revocationQueue,
            IAcmeNonceService nonceService,
            TimeProvider clock,
            CancellationToken ct) =>
        {
            return await HandleAcme(ctx, nonceService, async () =>
            {
                var jws = await parser.ParseAsync(ctx.Request, ct);

                var payload = jws.Payload?.RootElement
                    ?? throw new AcmeException("malformed", "Missing payload.");

                if (AcmeJson.OptionalString(payload, "certificate", "payload") is not string certB64)
                    return AcmeProblem("malformed", "Missing 'certificate' in payload.");

                byte[] derBytes;
                try
                {
                    derBytes = JwkConverter.Base64UrlDecode(certB64);
                }
                catch
                {
                    return AcmeProblem("malformed", "Invalid base64url-encoded 'certificate'.");
                }

                Org.BouncyCastle.X509.X509Certificate bcCert;
                string cn;
                try
                {
                    var certParser = new Org.BouncyCastle.X509.X509CertificateParser();
                    bcCert = certParser.ReadCertificate(derBytes);
                    var cnValues = bcCert.SubjectDN.GetValueList(Org.BouncyCastle.Asn1.X509.X509Name.CN);
                    if (cnValues.Count == 0)
                        return AcmeProblem("malformed", "Certificate has no Common Name.");
                    cn = cnValues[0]?.ToString() ?? string.Empty;
                }
                catch (Exception ex)
                {
                    return AcmeProblem("malformed", $"Failed to parse certificate: {ex.Message}");
                }

                var candidates = await db.CertificateRequests
                    .Where(r => r.CommonName == cn && (r.CertificatePem != null || r.PqcCertificatePem != null))
                    .ToListAsync(ct);

                CertificateRequest? foundRequest = null;
                Org.BouncyCastle.X509.X509Certificate? storedCertificate = null;

                var incomingSerial = bcCert.SerialNumber;
                foreach (var req in candidates)
                {
                    if (req.CertificatePem is not null)
                    {
                        try
                        {
                            var dbCert = QertumKeyCodec.ReadCertificatePem(req.CertificatePem);
                            if (dbCert is not null &&
                                dbCert.SerialNumber.Equals(incomingSerial) &&
                                dbCert.GetEncoded().AsSpan().SequenceEqual(derBytes))
                            {
                                foundRequest = req;
                                storedCertificate = dbCert;
                                break;
                            }
                        }
                        catch { }
                    }
                    if (req.PqcCertificatePem is not null)
                    {
                        try
                        {
                            var dbCert = QertumKeyCodec.ReadCertificatePem(req.PqcCertificatePem);
                            if (dbCert is not null &&
                                dbCert.SerialNumber.Equals(incomingSerial) &&
                                dbCert.GetEncoded().AsSpan().SequenceEqual(derBytes))
                            {
                                foundRequest = req;
                                storedCertificate = dbCert;
                                break;
                            }
                        }
                        catch { }
                    }
                }

                if (foundRequest is null || storedCertificate is null)
                {
                    return AcmeProblem("malformed", "Certificate not found or not issued by this CA.");
                }

                if (foundRequest.Status == CertificateRequestStatus.Revoked ||
                    foundRequest.Status == CertificateRequestStatus.PendingRevocation)
                {
                    return Results.Ok();
                }

                bool authorized = false;
                string performedBy;

                if (jws.Account is not null)
                {
                    if (foundRequest.RequestedBy == $"acme:{jws.Account.Id}")
                    {
                        authorized = true;
                    }
                    else
                    {
                        var dnsNames = new List<string>();
                        if (!string.IsNullOrEmpty(foundRequest.CommonName))
                        {
                            dnsNames.Add(foundRequest.CommonName);
                        }
                        if (!string.IsNullOrEmpty(foundRequest.PropertiesJson))
                        {
                            try
                            {
                                using var propDoc = JsonDocument.Parse(foundRequest.PropertiesJson);
                                if (propDoc.RootElement.TryGetProperty("dnsNames", out var dnsEl) && dnsEl.ValueKind == JsonValueKind.Array)
                                {
                                    foreach (var el in dnsEl.EnumerateArray())
                                    {
                                        var val = el.GetString();
                                        if (!string.IsNullOrEmpty(val) && !dnsNames.Contains(val, StringComparer.OrdinalIgnoreCase))
                                        {
                                            dnsNames.Add(val);
                                        }
                                    }
                                }
                            }
                            catch { }
                        }

                        // Only authorizations that are still inside their window count. Revocation is
                        // destructive and reaches certificates this account never requested, so proof
                        // of control that has aged out must not keep granting it.
                        var authzCutoff = clock.GetUtcNow().UtcDateTime;
                        var validAuths = await db.AcmeAuthorizations
                            .Where(auth => auth.Order.AccountId == jws.Account.Id &&
                                           auth.Status == "valid" &&
                                           auth.ExpiresAtUtc > authzCutoff &&
                                           auth.Order.ExpiresAtUtc > authzCutoff)
                            .Select(auth => new { auth.IdentifierValue, auth.Wildcard })
                            .ToListAsync(ct);

                        var authPairs = validAuths
                            .Select(a => (Identifier: a.IdentifierValue, a.Wildcard))
                            .ToList();

                        if (dnsNames.Count > 0 && dnsNames.All(name => IsCoveredByAuthorizations(name, authPairs)))
                        {
                            authorized = true;
                        }
                    }

                    performedBy = $"acme:{jws.Account.Id}";
                }
                else if (jws.EmbeddedJwk is not null)
                {
                    try
                    {
                        using var keyFromJwk = JwkConverter.ImportPublicKey(jws.EmbeddedJwk);
                        var spkiFromJwk = keyFromJwk.ExportSubjectPublicKeyInfo();

                        var spkiFromCert = QertumKeyCodec.ToSubjectPublicKeyInfo(
                            QertumKeyCodec.PublicKeyOf(storedCertificate)).GetEncoded();

                        if (spkiFromJwk.SequenceEqual(spkiFromCert))
                        {
                            authorized = true;
                        }
                    }
                    catch (Exception ex)
                    {
                        return AcmeProblem("unauthorized", $"Certificate public key verification failed: {ex.Message}");
                    }

                    performedBy = $"acme:cert:{(Guid)foundRequest.Id}";
                }
                else
                {
                    throw new AcmeException("unauthorized", "Neither account nor JWK is present to verify signature.");
                }

                if (!authorized)
                {
                    return AcmeProblem("unauthorized", "The signature key is not authorized to revoke this certificate.");
                }

                int reasonCode = 0;
                if (payload.TryGetProperty("reason", out var reasonProp) && reasonProp.ValueKind == JsonValueKind.Number
                    && !reasonProp.TryGetInt32(out reasonCode))
                    return AcmeProblem("malformed", "'reason' must be a whole number.");

                var mappedReason = MapAcmeRevocationReason(reasonCode);

                var result = await certReqService.MarkAsPendingRevocationAsync(foundRequest.Id, mappedReason, performedBy, ct);
                if (result is null)
                {
                    return AcmeProblem("serverInternal", "Failed to revoke certificate.");
                }

                revocationQueue.TrySignal();

                return Results.Ok();
            });
        });
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static async Task<IResult> HandleAcme(
        HttpContext ctx,
        IAcmeNonceService nonceService,
        Func<Task<IResult>> handler)
    {
        ctx.Response.Headers["Replay-Nonce"] = nonceService.GenerateNonce();
        ctx.Response.Headers.CacheControl = "no-store";
        try
        {
            return await handler();
        }
        catch (AcmeException ex)
        {
            return AcmeProblem(ex.ErrorType, ex.Message);
        }
        catch (EnrollmentPayloadTooLargeException)
        {
            return Results.Problem(title: "malformed", detail: "Enrollment payload is too large.",
                statusCode: StatusCodes.Status413PayloadTooLarge,
                type: "urn:ietf:params:acme:error:malformed");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The problem document is all the client gets, and ACME clients rarely show its detail.
            // Without this the cause of a 500 was recorded nowhere an operator could find it.
            // AcmeException above is deliberately not logged: it is the client's error, answered
            // as normal operation. The endpoint's name (verb and route template), not the decoded
            // request path: a path may carry a client-chosen %0A, which the console log would print
            // as a forged line.
            ctx.RequestServices.GetRequiredService<ILoggerFactory>()
                .CreateLogger(LogCategory)
                .LogError(ex, "ACME {Endpoint} failed with an unexpected server error.",
                    ctx.GetEndpoint()?.DisplayName);
            // The message stays in the log: it can name tables, files or other internals.
            return AcmeProblem("serverInternal", "The server could not process this request.");
        }
    }

    private static IResult AcmeProblem(string errorType, string detail)
    {
        var status = errorType switch
        {
            "badNonce" => 400,
            "malformed" => 400,
            // RFC 8555 §6.7: an algorithm, key or identifier type the server does not take is the
            // client's to change; unmapped, these fell through to 500.
            "badSignatureAlgorithm" => 400,
            "badPublicKey" => 400,
            "unsupportedIdentifier" => 400,
            "unauthorized" => 401,
            "accountDoesNotExist" => 400,
            // §7.3: both are the client's to fix, so they are 400s rather than the 500 an
            // unrecognized error type would otherwise fall through to.
            "invalidContact" => 400,
            "unsupportedContact" => 400,
            // RFC 8555 §6.7: the CSR is the client's to fix.
            "badCSR" => 400,
            // RFC 8555 §6.7: the server will not issue for this identifier — the client's to change.
            "rejectedIdentifier" => 400,
            "orderNotReady" => 403,
            "rateLimited" => 429,
            _ => 500
        };
        return Results.Problem(
            title: errorType,
            detail: detail,
            statusCode: status,
            type: $"urn:ietf:params:acme:error:{errorType}");
    }

    private static async Task<object> BuildOrderResponse(
        Guid orderId,
        CertificateRequestDbContext db,
        string baseUrl,
        DateTime now,
        CancellationToken ct)
    {
        var order = await db.AcmeOrders
            .Include(o => o.Authorizations)
            .FirstAsync(o => o.Id == orderId, ct);

        // A dictionary: RFC 8555 §7.1.3 makes "certificate" absent until the order is valid, and an
        // explicit null is not the same thing to a strict client.
        var map = new Dictionary<string, object?>
        {
            ["status"] = AcmeEffectiveStatus.Order(order, now),
            ["expires"] = Rfc3339(order.ExpiresAtUtc),
            ["identifiers"] = JsonSerializer.Deserialize<object>(order.IdentifiersJson),
            ["authorizations"] = order.Authorizations.Select(a => $"{baseUrl}/acme/authz/{a.Id}").ToList(),
            ["finalize"] = $"{baseUrl}/acme/finalize/{order.Id}"
        };

        if (order.Status == "valid")
            map["certificate"] = $"{baseUrl}/acme/certificate/{order.Id}";

        return map;
    }

    /// <summary>
    /// RFC 3339 in UTC with an explicit "Z". Values read back from the database have lost their
    /// <see cref="DateTimeKind"/>, and <c>ToString("O")</c> then prints no offset at all, which strict
    /// clients (certbot's pyrfc3339) reject.
    /// </summary>
    private static string Rfc3339(DateTime utc) =>
        DateTime.SpecifyKind(utc, DateTimeKind.Utc).ToString("yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'", System.Globalization.CultureInfo.InvariantCulture);

    private static object MapAccount(AcmeAccount account, string baseUrl) => new
    {
        status = account.Status,
        contact = account.ContactsJson is not null
            ? JsonSerializer.Deserialize<object>(account.ContactsJson)
            : null,
        // RFC 8555 §7.1.2.1. Advertised only because the endpoint behind it exists — a link that
        // answers 404 leaves a client unable to tell a missing feature from a broken server.
        orders = $"{baseUrl}/acme/account/{account.Id}/orders"
    };

    private static object MapAuthorization(AcmeAuthorization auth, string baseUrl, DateTime now)
    {
        // A dictionary rather than an anonymous type: RFC 8555 §7.1.4 defines "wildcard" as present
        // only when true, and an anonymous type cannot omit a member conditionally.
        var map = new Dictionary<string, object?>
        {
            ["status"] = AcmeEffectiveStatus.Authorization(auth, now),
            ["expires"] = Rfc3339(auth.ExpiresAtUtc),
            ["identifier"] = new { type = auth.IdentifierType, value = auth.IdentifierValue },
            ["challenges"] = auth.Challenges.Select(c => MapChallenge(c, baseUrl)).ToList()
        };

        if (auth.Wildcard)
            map["wildcard"] = true;

        return map;
    }

    private static AcmeChallenge NewChallenge(Guid authorizationId, string type) => new()
    {
        AuthorizationId = authorizationId,
        Type = type,
        Token = JwkConverter.Base64UrlEncode(
            System.Security.Cryptography.RandomNumberGenerator.GetBytes(32))
    };

    private static object MapChallenge(AcmeChallenge c, string baseUrl)
    {
        // RFC 8555 §8: "validated" is present only once the challenge is valid.
        var map = new Dictionary<string, object?>
        {
            ["type"] = c.Type,
            ["url"] = $"{baseUrl}/acme/challenge/{c.Id}",
            ["status"] = c.Status,
            ["token"] = c.Token
        };

        if (c.ValidatedAtUtc is { } validated)
            map["validated"] = Rfc3339(validated);

        return map;
    }

    private static string MapAcmeRevocationReason(int code) => code switch
    {
        0 => "unspecified",
        1 => "keyCompromise",
        2 => "cACompromise",
        3 => "affiliationChanged",
        4 => "superseded",
        5 => "cessationOfOperation",
        6 => "certificateHold",
        8 => "removeFromCRL",
        9 => "privilegeWithdrawn",
        10 => "aACompromise",
        _ => "unspecified"
    };

    private static readonly JsonSerializerOptions IdentifierJsonOptions =
        new() { PropertyNameCaseInsensitive = true };

    private sealed class AcmeIdentifier
    {
        public string Type { get; init; } = string.Empty;
        public string Value { get; init; } = string.Empty;
    }

    /// <summary>Leaf, then the issuing CA up to its root — for a single root exactly today's "leaf\nroot".</summary>
    internal static string BuildChainPem(string leafPem, IReadOnlyList<string> chain) =>
        string.Join("\n", new[] { leafPem }.Concat(chain));
}
