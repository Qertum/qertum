using System.Text.Json;
using Qertum.Services;
using Qertum.Services.Acme;
using Qertum.Services.Lifecycle;
using Microsoft.EntityFrameworkCore;

namespace Qertum.AcmeService;

/// <summary>
/// Background service that polls for challenges the client has triggered and verifies them:
/// http-01 by an outbound GET to http://{domain}/.well-known/acme-challenge/{token}, dns-01 by a
/// TXT lookup at _acme-challenge.{domain}.
/// </summary>
internal sealed class AcmeChallengeVerificationService(
    IServiceScopeFactory scopeFactory,
    IAcmeChallengeVerifier verifier,
    IDiagnosticEventLog diagnostics,
    ILogger<AcmeChallengeVerificationService> logger,
    ProtocolMetrics? metrics = null,
    TimeProvider? timeProvider = null) : BackgroundService
{
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
    private const int MaxAttempts = 3;
    private const string PerformedBy = "system";
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan RetryDelay = TimeSpan.FromSeconds(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ProcessPendingChallengesAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Error in ACME challenge verification loop; retrying.");
            }

            await Task.Delay(PollInterval, stoppingToken);
        }
    }

    internal async Task ProcessPendingChallengesAsync(CancellationToken ct)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();

        var now = _clock.GetUtcNow().UtcDateTime;
        var challenges = await db.AcmeChallenges
            .Include(c => c.Authorization).ThenInclude(a => a.Order).ThenInclude(o => o.Account)
            .Where(c => c.Status == "processing" && c.NextAttemptAfterUtc <= now &&
                        c.Authorization.ExpiresAtUtc > now && c.Authorization.Order.ExpiresAtUtc > now)
            .OrderBy(c => c.NextAttemptAfterUtc)
            .ToListAsync(ct);

        foreach (var challenge in challenges)
        {
            challenge.ValidationAttempts++;
            var domain = challenge.Authorization.IdentifierValue;
            var thumbprint = challenge.Authorization.Order.Account.JwkThumbprint;

            var result = challenge.Type switch
            {
                "http-01" => await verifier.VerifyHttp01Async(domain, challenge.Token, thumbprint, ct),
                "dns-01" => await verifier.VerifyDns01Async(domain, challenge.Token, thumbprint, ct),
                // Not a fallback to http-01: an unrecognized type means the row was written by code
                // this service does not know about, and guessing would validate the wrong thing.
                _ => AcmeVerificationResult.Failed(AcmeChallengeFailure.ConnectionFailed,
                    $"Unsupported challenge type '{challenge.Type}'.")
            };
            var (success, errorDetail) = result;
            var exhausted = !success && challenge.ValidationAttempts >= MaxAttempts;
            metrics?.AcmeChallenges.Add(1,
                new KeyValuePair<string, object?>("type", challenge.Type),
                new KeyValuePair<string, object?>("outcome", success ? "valid" : exhausted ? "failed" : "retry"),
                new KeyValuePair<string, object?>("failure", result.Failure.ToString()));
            var orderId = challenge.Authorization.OrderId;
            var identifier = challenge.Authorization.IdentifierValue;

            if (success)
            {
                challenge.Status = "valid";
                challenge.ValidatedAtUtc = _clock.GetUtcNow().UtcDateTime;
                diagnostics.Record(LifecycleSubjectTypes.AcmeOrder, orderId, DiagnosticActions.ChallengeValid, PerformedBy,
                    detail: $"{challenge.Type} for {identifier} validated on attempt {challenge.ValidationAttempts}.",
                    data: new { challengeType = challenge.Type, identifier, attempt = challenge.ValidationAttempts });
                logger.LogInformation("{Type} challenge {ChallengeId} validated for {Domain}.",
                    challenge.Type, challenge.Id, domain);

                // Persist challenge status before the AllAsync promotion check reads the DB.
                await db.SaveChangesAsync(ct);
                await TryPromoteAuthorizationAsync(challenge.Authorization, db, diagnostics, ct);
            }
            else if (challenge.ValidationAttempts >= MaxAttempts)
            {
                challenge.Status = "invalid";
                // Serialized, not interpolated: errorDetail is a raw exception message or an
                // operator-facing policy reason and may contain quotes or backslashes, which would
                // produce malformed JSON that is then served straight back to the ACME client.
                challenge.ErrorJson = JsonSerializer.Serialize(new
                {
                    type = "urn:ietf:params:acme:error:unauthorized",
                    detail = errorDetail ?? "Challenge validation failed."
                });
                diagnostics.Record(LifecycleSubjectTypes.AcmeOrder, orderId, DiagnosticActions.ChallengeAttemptFailed, PerformedBy,
                    category: result.Failure.ToString(), detail: errorDetail,
                    data: new { challengeType = challenge.Type, identifier, attempt = challenge.ValidationAttempts,
                        maxAttempts = MaxAttempts, nextAttemptAtUtc = (DateTime?)null });
                logger.LogWarning("{Type} challenge {ChallengeId} for {Domain} failed after {Attempts} attempts: {Detail}",
                    challenge.Type, challenge.Id, domain, challenge.ValidationAttempts, errorDetail);

                // Persist the challenge status before the sibling check reads the DB.
                await db.SaveChangesAsync(ct);
                await TryFailAuthorizationAsync(challenge.Authorization, db, diagnostics, metrics, ct);
            }
            else
            {
                // Scheduled, not slept: a Task.Delay here would stall every other challenge in the
                // batch behind one unreachable domain. The next poll picks this up once it is due.
                challenge.NextAttemptAfterUtc = _clock.GetUtcNow().UtcDateTime.Add(RetryDelay);
                diagnostics.Record(LifecycleSubjectTypes.AcmeOrder, orderId, DiagnosticActions.ChallengeAttemptFailed, PerformedBy,
                    category: result.Failure.ToString(), detail: errorDetail,
                    data: new { challengeType = challenge.Type, identifier, attempt = challenge.ValidationAttempts,
                        maxAttempts = MaxAttempts, nextAttemptAtUtc = (DateTime?)challenge.NextAttemptAfterUtc });
                logger.LogDebug("{Type} challenge {ChallengeId} attempt {Attempt}/{Max} failed: {Detail}. Next attempt at {Next:u}.",
                    challenge.Type, challenge.Id, challenge.ValidationAttempts, MaxAttempts, errorDetail,
                    challenge.NextAttemptAfterUtc);
            }
        }

        if (challenges.Count > 0)
            await db.SaveChangesAsync(ct);
    }

    private static async Task TryPromoteAuthorizationAsync(
        AcmeAuthorization auth,
        CertificateRequestDbContext db,
        IDiagnosticEventLog diagnostics,
        CancellationToken ct)
    {
        // RFC 8555 §7.1.6: an authorization becomes valid when ANY ONE of its challenges is valid.
        // A non-wildcard authorization offers both http-01 and dns-01, the client picks one, and
        // the other stays "pending" forever — only "processing" rows are ever polled — so requiring
        // all of them would leave every authorization stuck.
        //
        // Queried rather than read off auth.Challenges: the nav property is not eagerly loaded on
        // this path, so the collection is empty here and any in-memory predicate over it is
        // answering about nothing.
        var anyValid = await db.AcmeChallenges
            .Where(c => c.AuthorizationId == auth.Id)
            .AnyAsync(c => c.Status == "valid", ct);

        if (!anyValid) return;

        auth.Status = "valid";
        diagnostics.Record(LifecycleSubjectTypes.AcmeOrder, auth.OrderId, DiagnosticActions.AuthorizationValid, PerformedBy,
            detail: $"Authorization for {auth.IdentifierValue} is valid.");
        // Persist authz status so the AllAsync DB query below sees the updated value.
        await db.SaveChangesAsync(ct);

        // Order is ready when all its authorizations are valid
        var order = auth.Order;
        var allAuthsValid = await db.AcmeAuthorizations
            .Where(a => a.OrderId == order.Id)
            .AllAsync(a => a.Status == "valid", ct);

        if (allAuthsValid && order.Status == "pending")
        {
            order.Status = "ready";
            diagnostics.Record(LifecycleSubjectTypes.AcmeOrder, order.Id, DiagnosticActions.OrderReady, PerformedBy,
                detail: "Every authorization is valid; the order is ready to finalize.");
        }
    }

    /// <summary>
    /// Fails the authorization and its order, but only once the client has no way left to succeed.
    /// A challenge that exhausted its attempts is terminal for itself; it is terminal for the
    /// authorization only when no sibling is still pending or processing, and none has already
    /// passed. Failing eagerly would let an http-01 challenge the client never attempted destroy an
    /// authorization it satisfied by dns-01.
    /// </summary>
    private static async Task TryFailAuthorizationAsync(
        AcmeAuthorization auth,
        CertificateRequestDbContext db,
        IDiagnosticEventLog diagnostics,
        ProtocolMetrics? metrics,
        CancellationToken ct)
    {
        var siblings = await db.AcmeChallenges
            .Where(c => c.AuthorizationId == auth.Id)
            .Select(c => c.Status)
            .ToListAsync(ct);

        if (siblings.Any(status => status is "pending" or "processing" or "valid"))
            return;

        auth.Status = "invalid";
        auth.Order.Status = "invalid";
        metrics?.AcmeOrders.Add(1, new KeyValuePair<string, object?>("outcome", "invalid"));
        diagnostics.Record(LifecycleSubjectTypes.AcmeOrder, auth.OrderId, DiagnosticActions.AuthorizationInvalid, PerformedBy,
            detail: $"No challenge for {auth.IdentifierValue} can still succeed; the authorization and its order are invalid.");
        await db.SaveChangesAsync(ct);
    }
}
