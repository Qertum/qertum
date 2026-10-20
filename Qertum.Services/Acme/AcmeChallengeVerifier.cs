using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Qertum.Services.Acme;

public interface IAcmeChallengeVerifier
{
    Task<AcmeVerificationResult> VerifyHttp01Async(
        string domain, string token, string accountKeyThumbprint, CancellationToken ct = default);

    /// <summary>
    /// Verifies a dns-01 challenge by reading TXT records at <c>_acme-challenge.{baseDomain}</c>.
    /// <paramref name="baseDomain"/> is the authorization's identifier value, which is already the
    /// base name for a wildcard — a '*' is never part of a DNS query name.
    /// </summary>
    Task<AcmeVerificationResult> VerifyDns01Async(
        string baseDomain, string token, string accountKeyThumbprint, CancellationToken ct = default);
}

/// <summary>
/// Thrown by the connect callback when the address policy rejects a resolved address. Carries the
/// operator-facing reason out through <see cref="HttpRequestException"/>'s inner exception so the
/// challenge records why it failed rather than a generic connection error.
/// </summary>
public sealed class AcmeAddressDeniedException(string message) : Exception(message);

public sealed class AcmeChallengeVerifier(
    IHttpClientFactory httpClientFactory,
    IAcmeDnsResolver dnsResolver,
    ILogger<AcmeChallengeVerifier> logger) : IAcmeChallengeVerifier
{
    public async Task<AcmeVerificationResult> VerifyHttp01Async(
        string domain,
        string token,
        string accountKeyThumbprint,
        CancellationToken ct = default)
    {
        var url = $"http://{domain}/.well-known/acme-challenge/{token}";
        var expected = $"{token}.{accountKeyThumbprint}";
        // Shown in details instead of the real URL: the token proves control of the name.
        var shownUrl = $"http://{domain}/.well-known/acme-challenge/<token>";

        try
        {
            using var client = httpClientFactory.CreateClient("acme-challenge");
            using var response = await client.GetAsync(url, ct);

            if (response.StatusCode != HttpStatusCode.OK)
                return AcmeVerificationResult.Failed(AcmeChallengeFailure.HttpStatus, $"HTTP {(int)response.StatusCode} from {shownUrl}");

            var body = await response.Content.ReadAsStringAsync(ct);
            var actual = body.Trim();

            if (string.Equals(actual, expected, StringComparison.Ordinal))
                return AcmeVerificationResult.Valid;

            if (logger.IsEnabled(LogLevel.Debug))
            {
                logger.LogDebug("http-01 key-auth mismatch for {Domain}. Expected: {Expected}, Got: {Actual}",
                    domain, expected, actual);
            }
            return AcmeVerificationResult.Failed(AcmeChallengeFailure.KeyAuthorizationMismatch, $"Key authorization mismatch for domain '{domain}'.");
        }
        catch (HttpRequestException ex)
        {
            // A policy rejection surfaces here wrapped by the socket handler. Report the specific
            // reason instead of the generic "connection failed" the wrapper carries.
            var denied = Unwrap<AcmeAddressDeniedException>(ex);
            if (denied is not null)
            {
                logger.LogInformation("http-01 challenge for {Domain} denied by address policy: {Reason}",
                    domain, denied.Message);
                return AcmeVerificationResult.Failed(AcmeChallengeFailure.AllowlistDenied, denied.Message);
            }

            if (logger.IsEnabled(LogLevel.Debug))
                logger.LogDebug(ex, "http-01 outbound request failed for {Domain}", domain);
            return AcmeVerificationResult.Failed(AcmeChallengeFailure.ConnectionFailed, ex.Message.Replace(token, "<token>", StringComparison.Ordinal));
        }
        catch (AcmeAddressDeniedException ex)
        {
            return AcmeVerificationResult.Failed(AcmeChallengeFailure.AllowlistDenied, ex.Message);
        }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            // The client's own 10-second timeout, not a shutdown.
            return AcmeVerificationResult.Failed(AcmeChallengeFailure.Timeout, $"Timeout reaching {shownUrl}");
        }
    }

    public async Task<AcmeVerificationResult> VerifyDns01Async(
        string baseDomain,
        string token,
        string accountKeyThumbprint,
        CancellationToken ct = default)
    {
        var name = $"_acme-challenge.{baseDomain}";

        // RFC 8555 §8.4: dns-01 publishes the base64url SHA-256 digest of the key authorization,
        // where http-01 serves the key authorization itself. Publishing the raw value is a common
        // client mistake, so it must not be accepted here.
        var expected = JwkConverter.Base64UrlEncode(
            SHA256.HashData(Encoding.UTF8.GetBytes($"{token}.{accountKeyThumbprint}")));

        var lookup = await dnsResolver.ResolveTxtAsync(name, ct);

        if (!lookup.Succeeded)
            return AcmeVerificationResult.Failed(AcmeChallengeFailure.DnsLookupFailed, lookup.ErrorDetail ?? $"DNS lookup for '{name}' failed.");

        if (lookup.Records.Count == 0)
            return AcmeVerificationResult.Failed(AcmeChallengeFailure.DnsNoTxtRecord, $"No TXT record found at '{name}'.");

        // Any record may carry the digest: several orders for one name publish side by side.
        if (lookup.Records.Any(record => string.Equals(record.Trim(), expected, StringComparison.Ordinal)))
            return AcmeVerificationResult.Valid;

        if (logger.IsEnabled(LogLevel.Debug))
        {
            logger.LogDebug("dns-01 digest mismatch at {Name}. Expected: {Expected}, Got: {Actual}",
                name, expected, string.Join(", ", lookup.Records));
        }

        return AcmeVerificationResult.Failed(AcmeChallengeFailure.KeyAuthorizationMismatch, $"Key authorization mismatch at '{name}'.");
    }

    private static TException? Unwrap<TException>(Exception exception) where TException : Exception
    {
        for (var current = exception.InnerException; current is not null; current = current.InnerException)
        {
            if (current is TException match)
                return match;
        }

        return null;
    }
}
