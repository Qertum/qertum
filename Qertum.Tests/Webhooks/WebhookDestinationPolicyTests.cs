using System.Net;
using Qertum.Services;
using Qertum.Services.Webhooks;

namespace Qertum.Tests.Webhooks;

public sealed class WebhookDestinationPolicyTests
{
    [Theory]
    [InlineData("https://hook.invalid./x", "hook.invalid", 443)]
    [InlineData("https://HOOK.INVALID:8443/x", "hook.invalid", 8443)]
    [InlineData("http://2130706433/x", "127.0.0.1", 80)]
    [InlineData("https://[::ffff:127.0.0.1]/x", "127.0.0.1", 443)]
    public void TargetNormalizesHostAndEffectivePort(string raw, string host, int port)
    {
        Assert.True(WebhookDestinationTarget.TryParse(raw, out var target, out var error), error);
        Assert.Equal(host, target!.Host);
        Assert.Equal(port, target.Port);
    }

    [Theory]
    [InlineData("https://user:pass@hook.invalid/x")]
    [InlineData("https://hook.invalid/x#fragment")]
    [InlineData("https://{resourceName}.invalid/x")]
    [InlineData("https://hook.invalid:{resourceId}/x")]
    [InlineData("ftp://hook.invalid/x")]
    public void TargetRejectsUnsafeUrlShapes(string raw)
        => Assert.False(WebhookDestinationTarget.TryParse(raw, out _, out _));

    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("2606:4700:4700::1111", true)]
    [InlineData("127.0.0.1", false)]
    [InlineData("::1", false)]
    [InlineData("::ffff:127.0.0.1", false)]
    [InlineData("10.0.0.1", false)]
    [InlineData("172.16.0.1", false)]
    [InlineData("192.168.0.1", false)]
    [InlineData("100.100.100.200", false)]
    [InlineData("169.254.169.254", false)]
    [InlineData("fd00:ec2::254", false)]
    [InlineData("fe80::1", false)]
    [InlineData("ff02::1", false)]
    [InlineData("0.0.0.0", false)]
    public void AnyPublicAllowsOnlyPublicAddresses(string address, bool expected)
    {
        var target = Target("https://hook.invalid/x");
        var decision = WebhookAddressPolicy.Check(Snapshot(), target, [IPAddress.Parse(address)]);
        Assert.Equal(expected, decision.Allowed);
    }

    [Fact]
    public void MixedDnsAnswerIsRefusedInFull()
    {
        var decision = WebhookAddressPolicy.Check(Snapshot(), Target("https://hook.invalid/x"),
            [IPAddress.Parse("8.8.8.8"), IPAddress.Loopback]);
        Assert.False(decision.Allowed);
    }

    [Fact]
    public void MissingDnsAnswerAndUninitializedPolicyFailClosed()
    {
        var target = Target("https://hook.invalid/x");
        Assert.False(WebhookAddressPolicy.Check(Snapshot(), target, []).Allowed);
        Assert.False(WebhookAddressPolicy.Check(new(false, WebhookPublicMode.AnyPublic, []), target,
            [IPAddress.Parse("8.8.8.8")]).Allowed);
    }

    [Fact]
    public void ListedPublicRequiresExactSchemeHostAndPort()
    {
        var rule = Rule(WebhookDestinationRuleKind.Public, "https", "hook.invalid", 443);
        var snapshot = new WebhookDestinationPolicySnapshot(true, WebhookPublicMode.ListedPublic, [rule]);
        var address = new[] { IPAddress.Parse("8.8.8.8") };

        Assert.True(WebhookAddressPolicy.Check(snapshot, Target("https://hook.invalid/x"), address).Allowed);
        Assert.False(WebhookAddressPolicy.Check(snapshot, Target("http://hook.invalid/x"), address).Allowed);
        Assert.False(WebhookAddressPolicy.Check(snapshot, Target("https://hook.invalid:8443/x"), address).Allowed);
        Assert.False(WebhookAddressPolicy.Check(snapshot, Target("https://other.invalid/x"), address).Allowed);
    }

    [Fact]
    public void InternalRulePinsEveryResolvedAddress()
    {
        var rule = Rule(WebhookDestinationRuleKind.Internal, "https", "internal.invalid", 443,
            IPAddress.Parse("10.0.0.7"));
        var snapshot = new WebhookDestinationPolicySnapshot(true, WebhookPublicMode.AnyPublic, [rule]);
        var target = Target("https://internal.invalid/x");

        Assert.True(WebhookAddressPolicy.Check(snapshot, target, [IPAddress.Parse("10.0.0.7")]).Allowed);
        Assert.False(WebhookAddressPolicy.Check(snapshot, target,
            [IPAddress.Parse("10.0.0.7"), IPAddress.Parse("10.0.0.8")]).Allowed);
        Assert.False(WebhookAddressPolicy.Check(snapshot, Target("https://other.invalid/x"),
            [IPAddress.Parse("10.0.0.7")]).Allowed);
    }

    [Fact]
    public void PublicAndPinnedInternalAnswersCannotShareAnOrigin()
    {
        var rule = Rule(WebhookDestinationRuleKind.Internal, "https", "internal.invalid", 443,
            IPAddress.Parse("10.0.0.7"));
        var snapshot = new WebhookDestinationPolicySnapshot(true, WebhookPublicMode.AnyPublic, [rule]);

        Assert.False(WebhookAddressPolicy.Check(snapshot, Target("https://internal.invalid/x"),
            [IPAddress.Parse("8.8.8.8"), IPAddress.Parse("10.0.0.7")]).Allowed);
    }

    [Fact]
    public void OneInternalRuleMustCoverEveryDnsAnswer()
    {
        var first = Rule(WebhookDestinationRuleKind.Internal, "https", "internal.invalid", 443,
            IPAddress.Parse("10.0.0.7"));
        var second = Rule(WebhookDestinationRuleKind.Internal, "https", "internal.invalid", 443,
            IPAddress.Parse("10.0.0.8"));
        var snapshot = new WebhookDestinationPolicySnapshot(true, WebhookPublicMode.AnyPublic, [first, second]);

        Assert.False(WebhookAddressPolicy.Check(snapshot, Target("https://internal.invalid/x"),
            [IPAddress.Parse("10.0.0.7"), IPAddress.Parse("10.0.0.8")]).Allowed);
    }

    [Theory]
    [InlineData("169.254.169.254")]
    [InlineData("fd00:ec2::254")]
    [InlineData("fe80::1")]
    public void InternalRuleCannotAllowAlwaysBlockedAddress(string address)
    {
        var ip = IPAddress.Parse(address);
        var rule = Rule(WebhookDestinationRuleKind.Internal, "https", "internal.invalid", 443, ip);
        var snapshot = new WebhookDestinationPolicySnapshot(true, WebhookPublicMode.AnyPublic, [rule]);

        Assert.False(WebhookAddressPolicy.Check(snapshot, Target("https://internal.invalid/x"), [ip]).Allowed);
    }

    [Fact]
    public void DisabledRuleNeverAllowsAddress()
    {
        var rule = Rule(WebhookDestinationRuleKind.Internal, "https", "internal.invalid", 443,
            IPAddress.Parse("10.0.0.7")) with { Enabled = false };
        var snapshot = new WebhookDestinationPolicySnapshot(true, WebhookPublicMode.AnyPublic, [rule]);

        Assert.False(WebhookAddressPolicy.Check(snapshot, Target("https://internal.invalid/x"),
            [IPAddress.Parse("10.0.0.7")]).Allowed);
    }

    private static WebhookDestinationTarget Target(string url)
    {
        Assert.True(WebhookDestinationTarget.TryParse(url, out var target, out var error), error);
        return target!;
    }

    private static WebhookDestinationPolicySnapshot Snapshot()
        => new(true, WebhookPublicMode.AnyPublic, []);

    private static WebhookDestinationRuleSnapshot Rule(
        WebhookDestinationRuleKind kind, string scheme, string host, int port, params IPAddress[] pins)
        => new(Guid.NewGuid(), "Admin", kind, scheme, host, port, true, pins);
}
