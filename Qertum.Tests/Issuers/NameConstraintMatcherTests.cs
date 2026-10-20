using System.Net;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

public sealed class NameConstraintMatcherTests
{
    [Theory]
    [InlineData("corp.example", "corp.example", true)]
    [InlineData("www.corp.example", "corp.example", true)]
    [InlineData("WWW.Corp.Example.", "corp.example", true)]
    [InlineData("evilcorp.example", "corp.example", false)]
    [InlineData("corp.example.evil", "corp.example", false)]
    [InlineData("*.corp.example", "corp.example", true)]
    [InlineData("*.example", "corp.example", false)]
    [InlineData("", "corp.example", false)]
    public void DnsWithin_UsesLabelBoundaries(string name, string suffix, bool expected) =>
        Assert.Equal(expected, NameConstraintMatcher.DnsWithin(name, suffix));

    [Theory]
    [InlineData("10.1.2.3", "10.0.0.0/8", true)]
    [InlineData("11.1.2.3", "10.0.0.0/8", false)]
    [InlineData("::1", "10.0.0.0/8", false)]
    [InlineData("2001:db8::5", "2001:db8::/32", true)]
    public void IpWithin_MatchesFamilyAndPrefix(string ip, string cidr, bool expected) =>
        Assert.Equal(expected, NameConstraintMatcher.IpWithin(IPAddress.Parse(ip), cidr));

    [Theory]
    [InlineData("10.1.0.0/16", "10.0.0.0/8", true)]
    [InlineData("10.0.0.0/8", "10.1.0.0/16", false)]
    [InlineData("10.0.0.0/8", "10.0.0.0/8", true)]
    public void CidrWithin(string inner, string outer, bool expected) =>
        Assert.Equal(expected, NameConstraintMatcher.CidrWithin(inner, outer));

    [Theory]
    [InlineData("a.corp.example", "corp.example", true)]
    [InlineData("corp.example", "a.corp.example", false)]
    public void SuffixWithin(string inner, string outer, bool expected) =>
        Assert.Equal(expected, NameConstraintMatcher.SuffixWithin(inner, outer));
}
