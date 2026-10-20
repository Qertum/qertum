using System.Security.Cryptography;
using System.Text;
using Qertum.Services.Acme;
using Microsoft.Extensions.Logging.Abstractions;

namespace Qertum.Tests;

file sealed class FakeDnsResolver(DnsTxtLookupResult result) : IAcmeDnsResolver
{
    public string? QueriedName { get; private set; }

    public Task<DnsTxtLookupResult> ResolveTxtAsync(string name, CancellationToken ct = default)
    {
        QueriedName = name;
        return Task.FromResult(result);
    }
}

/// <summary>The dns-01 path never touches HTTP; this exists only to satisfy the constructor.</summary>
file sealed class NoOpHttpClientFactory : IHttpClientFactory
{
    public HttpClient CreateClient(string name) => new();
}

public sealed class AcmeDns01VerifierTests
{
    private const string Token = "token-value";
    private const string Thumbprint = "thumbprint-value";

    private static string ExpectedDigest() =>
        JwkConverter.Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes($"{Token}.{Thumbprint}")));

    private static AcmeChallengeVerifier CreateVerifier(IAcmeDnsResolver resolver) =>
        new(new NoOpHttpClientFactory(), resolver, NullLogger<AcmeChallengeVerifier>.Instance);

    [Fact]
    public async Task QueriesTheUnderscorePrefixedNameAndAcceptsTheDigest()
    {
        var resolver = new FakeDnsResolver(new DnsTxtLookupResult(true, [ExpectedDigest()], null));
        var verifier = CreateVerifier(resolver);

        var (success, error) = await verifier.VerifyDns01Async(
            "example.com", Token, Thumbprint, TestContext.Current.CancellationToken);

        Assert.True(success, error);
        Assert.Equal("_acme-challenge.example.com", resolver.QueriedName);
    }

    [Fact]
    public async Task AcceptsWhenOneOfSeveralRecordsMatches()
    {
        // Concurrent orders for one name legitimately publish several records (RFC 8555 §8.4).
        var resolver = new FakeDnsResolver(
            new DnsTxtLookupResult(true, ["some-other-order-digest", ExpectedDigest()], null));
        var verifier = CreateVerifier(resolver);

        var (success, _) = await verifier.VerifyDns01Async(
            "example.com", Token, Thumbprint, TestContext.Current.CancellationToken);

        Assert.True(success);
    }

    [Fact]
    public async Task RejectsARecordThatIsTheRawKeyAuthorization()
    {
        // dns-01 publishes the SHA-256 digest, not the raw key authorization that http-01 serves.
        var resolver = new FakeDnsResolver(
            new DnsTxtLookupResult(true, [$"{Token}.{Thumbprint}"], null));
        var verifier = CreateVerifier(resolver);

        var (success, error) = await verifier.VerifyDns01Async(
            "example.com", Token, Thumbprint, TestContext.Current.CancellationToken);

        Assert.False(success);
        Assert.Contains("mismatch", error);
    }

    [Fact]
    public async Task ReportsAnEmptyAnswerDistinctlyFromALookupFailure()
    {
        var empty = CreateVerifier(new FakeDnsResolver(new DnsTxtLookupResult(true, [], null)));
        var failed = CreateVerifier(new FakeDnsResolver(new DnsTxtLookupResult(false, [], "SERVFAIL")));
        var ct = TestContext.Current.CancellationToken;

        var (emptySuccess, emptyError) = await empty.VerifyDns01Async("example.com", Token, Thumbprint, ct);
        var (failedSuccess, failedError) = await failed.VerifyDns01Async("example.com", Token, Thumbprint, ct);

        Assert.False(emptySuccess);
        Assert.Contains("No TXT record", emptyError);
        Assert.False(failedSuccess);
        Assert.Contains("SERVFAIL", failedError);
    }

    [Fact]
    public async Task EachDnsFailure_CarriesItsOwnCategory()
    {
        var ct = TestContext.Current.CancellationToken;

        var failed = await CreateVerifier(new FakeDnsResolver(new DnsTxtLookupResult(false, [], "SERVFAIL")))
            .VerifyDns01Async("example.com", Token, Thumbprint, ct);
        var empty = await CreateVerifier(new FakeDnsResolver(new DnsTxtLookupResult(true, [], null)))
            .VerifyDns01Async("example.com", Token, Thumbprint, ct);
        var wrong = await CreateVerifier(new FakeDnsResolver(new DnsTxtLookupResult(true, ["not-the-digest"], null)))
            .VerifyDns01Async("example.com", Token, Thumbprint, ct);
        var right = await CreateVerifier(new FakeDnsResolver(new DnsTxtLookupResult(true, [ExpectedDigest()], null)))
            .VerifyDns01Async("example.com", Token, Thumbprint, ct);

        Assert.Equal(AcmeChallengeFailure.DnsLookupFailed, failed.Failure);
        Assert.Equal(AcmeChallengeFailure.DnsNoTxtRecord, empty.Failure);
        Assert.Equal(AcmeChallengeFailure.KeyAuthorizationMismatch, wrong.Failure);
        Assert.Equal(AcmeChallengeFailure.None, right.Failure);
        Assert.True(right.Success);
    }
}
