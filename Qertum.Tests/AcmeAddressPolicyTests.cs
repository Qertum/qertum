using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Qertum.Services;
using Qertum.Services.Acme;

namespace Qertum.Tests;

/// <summary>
/// Regression tests for the former IMPROVEMENTS.md audit §3.2 — ACME order identifiers reached the outbound challenge
/// request unvalidated, letting an unauthenticated caller drive GETs to loopback, cloud metadata, and
/// any host routable from the ACME service.
/// </summary>
public sealed class AcmeAddressPolicyTests
{
    private static readonly AcmeAddressPolicy Policy = new(NullLogger<AcmeAddressPolicy>.Instance);

    private static string Networks(params string[] entries) => JsonSerializer.Serialize(entries);

    private static AddressDecision Evaluate(string address, string? networksJson) =>
        Policy.Evaluate(IPAddress.Parse(address), "challenge.example", networksJson);

    // ── Exclusive allowlist ───────────────────────────────────────────────────

    [Fact]
    public void EmptyAllowlistDeniesEverything()
    {
        // The list is exclusive: nothing is reachable until an operator configures a range.
        Assert.False(Evaluate("93.184.216.34", null).Allowed);
        Assert.False(Evaluate("93.184.216.34", "").Allowed);
        Assert.False(Evaluate("93.184.216.34", Networks()).Allowed);
    }

    [Fact]
    public void EmptyAllowlistExplainsHowToFixIt()
    {
        var decision = Evaluate("93.184.216.34", null);

        Assert.Equal(AcmeAddressPolicy.NoNetworksConfigured, decision.DenyReason);
    }

    [Fact]
    public void PublicAddressIsNotImplicitlyAllowed()
    {
        // Additive semantics would let this through; the design is deliberately exclusive.
        Assert.False(Evaluate("93.184.216.34", Networks("10.0.0.0/8")).Allowed);
    }

    [Fact]
    public void AddressInsideAListedRangeIsAllowed()
    {
        Assert.True(Evaluate("10.1.2.3", Networks("10.1.0.0/16")).Allowed);
    }

    [Fact]
    public void AddressOutsideEveryListedRangeIsDenied()
    {
        var decision = Evaluate("10.9.9.9", Networks("10.1.0.0/16", "192.168.4.0/24"));

        Assert.False(decision.Allowed);
        Assert.Contains("not in the configured allowed networks", decision.DenyReason);
    }

    [Fact]
    public void LoopbackIsReachableOnlyWhenExplicitlyListed()
    {
        Assert.False(Evaluate("127.0.0.1", Networks("10.0.0.0/8")).Allowed);
        Assert.True(Evaluate("127.0.0.1", Networks("127.0.0.0/8")).Allowed);
    }

    [Fact]
    public void ASingleAddressEntryIsTreatedAsAOneHostRange()
    {
        Assert.True(Evaluate("10.0.0.5", Networks("10.0.0.5")).Allowed);
        Assert.False(Evaluate("10.0.0.6", Networks("10.0.0.5")).Allowed);
    }

    // ── Link-local hard deny ──────────────────────────────────────────────────

    [Fact]
    public void CloudMetadataAddressIsDeniedWithAnEmptyList()
    {
        Assert.False(Evaluate("169.254.169.254", null).Allowed);
    }

    [Fact]
    public void CloudMetadataAddressIsDeniedEvenWhenExplicitlyListed()
    {
        // The hard deny must survive an operator entering a range that covers it, deliberately or
        // by pasting 0.0.0.0/0.
        var explicitEntry = Evaluate("169.254.169.254", Networks("169.254.0.0/16"));
        var catchAll = Evaluate("169.254.169.254", Networks("0.0.0.0/0"));

        Assert.False(explicitEntry.Allowed);
        Assert.False(catchAll.Allowed);
        Assert.Contains("link-local", explicitEntry.DenyReason);
    }

    [Fact]
    public void IPv6LinkLocalIsDeniedEvenWhenExplicitlyListed()
    {
        Assert.False(Evaluate("fe80::1", Networks("fe80::/10")).Allowed);
    }

    [Fact]
    public void CatchAllStillAllowsOrdinaryAddresses()
    {
        // Guards against the hard deny being implemented as "deny everything when 0.0.0.0/0 is used".
        Assert.True(Evaluate("93.184.216.34", Networks("0.0.0.0/0")).Allowed);
    }

    // ── IPv6 ──────────────────────────────────────────────────────────────────

    [Fact]
    public void IPv6UniqueLocalMatchesItsRange()
    {
        Assert.True(Evaluate("fd00:1234::5", Networks("fd00:1234::/32")).Allowed);
        Assert.False(Evaluate("fd00:9999::5", Networks("fd00:1234::/32")).Allowed);
    }

    [Fact]
    public void IPv4MappedAddressIsMatchedAgainstIPv4Ranges()
    {
        // A resolver may report 10.0.0.5 as ::ffff:10.0.0.5; an operator's IPv4 entry must still apply.
        Assert.True(Evaluate("::ffff:10.0.0.5", Networks("10.0.0.0/8")).Allowed);
    }

    [Fact]
    public void IPv4MappedMetadataAddressIsStillDenied()
    {
        Assert.False(Evaluate("::ffff:169.254.169.254", Networks("0.0.0.0/0")).Allowed);
    }

    // ── Malformed stored configuration ────────────────────────────────────────

    [Fact]
    public void MalformedEntryIsIgnoredWithoutDisablingTheRest()
    {
        // The validator blocks these on save, so this only arises from a hand-edited database.
        // One bad entry must not become a total ACME outage.
        var networks = Networks("not-a-cidr", "10.0.0.0/8");

        Assert.True(Evaluate("10.0.0.5", networks).Allowed);
        Assert.False(Evaluate("93.184.216.34", networks).Allowed);
    }

    [Fact]
    public void MalformedJsonIsTreatedAsAnEmptyList()
    {
        var decision = Evaluate("10.0.0.5", "{not json");

        Assert.False(decision.Allowed);
        Assert.Equal(AcmeAddressPolicy.NoNetworksConfigured, decision.DenyReason);
    }

    // ── Entry parsing ─────────────────────────────────────────────────────────

    [Theory]
    [InlineData("10.0.0.0/8")]
    [InlineData("192.168.4.0/24")]
    [InlineData("fd00::/8")]
    [InlineData("10.0.0.5")]
    [InlineData("  10.0.0.0/8  ")]
    public void ValidEntriesParse(string entry) =>
        Assert.True(AcmeAddressPolicy.TryParseNetwork(entry, out _));

    [Theory]
    [InlineData("not-a-cidr")]
    [InlineData("10.0.0.0/99")]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("10.0.0.0/8extra")]
    public void InvalidEntriesDoNotParse(string? entry) =>
        Assert.False(AcmeAddressPolicy.TryParseNetwork(entry, out _));
}

/// <summary>
/// Parse-time identifier validation at <c>new-order</c>, the first of the two checks: it keeps IP
/// literals, embedded delimiters and wildcards out of the system before an order row exists.
/// </summary>
public sealed class AcmeIdentifierValidationTests
{
    [Theory]
    [InlineData("acme-test.local")]
    [InlineData("manual.local")]
    [InlineData("api.example.com")]
    [InlineData("a.b.c.d.example.com")]
    [InlineData("xn--bcher-kva.example")]
    public void AcceptsOrdinaryDnsNames(string value)
    {
        Assert.True(AcmeEndpointMappings.IsValidDnsIdentifier(value, out _));
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.169.254")]
    [InlineData("::1")]
    public void RejectsIpLiterals(string value)
    {
        Assert.False(AcmeEndpointMappings.IsValidDnsIdentifier(value, out _));
    }

    [Theory]
    [InlineData("evil.com:6379")]
    [InlineData("evil.com/path")]
    [InlineData("evil.com#frag")]
    [InlineData("evil.com?q=1")]
    [InlineData("user@evil.com")]
    public void RejectsEmbeddedDelimiters(string value)
    {
        Assert.False(AcmeEndpointMappings.IsValidDnsIdentifier(value, out _));
    }

    [Theory]
    [InlineData("*.example.com")]
    [InlineData("*.sub.example.com")]
    public void AcceptsLeftmostWildcards(string value)
    {
        Assert.True(AcmeEndpointMappings.IsValidDnsIdentifier(value, out var reason), reason);
    }

    [Theory]
    [InlineData("*")]
    [InlineData("*.")]
    [InlineData("*.*.example.com")]
    [InlineData("foo.*.example.com")]
    [InlineData("*example.com")]
    public void RejectsWildcardsAnywhereButTheLeftmostLabel(string value)
    {
        Assert.False(AcmeEndpointMappings.IsValidDnsIdentifier(value, out var reason));
        Assert.NotEmpty(reason);
    }

    [Fact]
    public void TryParseWildcard_StripsThePrefixForAWildcard()
    {
        Assert.True(AcmeEndpointMappings.TryParseWildcard("*.example.com", out var baseName));
        Assert.Equal("example.com", baseName);
    }

    [Fact]
    public void TryParseWildcard_LeavesAPlainNameAlone()
    {
        Assert.False(AcmeEndpointMappings.TryParseWildcard("example.com", out var baseName));
        Assert.Equal("example.com", baseName);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void RejectsEmptyValues(string? value)
    {
        Assert.False(AcmeEndpointMappings.IsValidDnsIdentifier(value, out _));
    }

    [Fact]
    public void RejectsOverlongNames()
    {
        var tooLong = string.Join('.', Enumerable.Repeat("label", 60));

        Assert.False(AcmeEndpointMappings.IsValidDnsIdentifier(tooLong, out var reason));
        Assert.Contains("maximum DNS name length", reason);
    }
}
