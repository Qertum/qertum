using System.Text.Json;
using Qertum.Services;

namespace Qertum.Tests.Validators;

/// <summary>
/// PropertiesJson had no length limit and the SAN lists no size limit: any holder of certificates.create could send a
/// near-body-limit list of names that validation, policy, storage and certificate generation all walk (AI Scan,
/// 1.0.0-rc6). A request now carries at most 100 names in all, the ACME order limit, and at most 64 KiB of JSON.
/// </summary>
public sealed class CertificateRequestSizeLimitTests
{
    private static string Names(int dns, int ip = 0, int email = 0, int upn = 0) => JsonSerializer.Serialize(new
    {
        dnsNames = Enumerable.Range(0, dns).Select(i => $"host{i}.example.com"),
        ipAddresses = Enumerable.Range(0, ip).Select(i => $"10.0.{i / 250}.{i % 250 + 1}"),
        emailAddresses = Enumerable.Range(0, email).Select(i => $"user{i}@example.com"),
        userPrincipalNames = Enumerable.Range(0, upn).Select(i => $"upn{i}@example.com"),
    });

    [Fact]
    public void AHundredNames_AreAccepted() =>
        Assert.True(CertificateRequestValidator.ValidatePropertiesJson(Names(40, 20, 20, 20), out var error), error);

    [Theory]
    [InlineData(101, 0, 0, 0)]
    [InlineData(40, 21, 20, 20)]
    [InlineData(0, 0, 0, 101)]
    public void MoreThanAHundredNamesInAll_AreRefused(int dns, int ip, int email, int upn)
    {
        Assert.False(CertificateRequestValidator.ValidatePropertiesJson(Names(dns, ip, email, upn), out var error));
        Assert.Contains("at most 100 subject alternative names", error);
    }

    [Fact]
    public void OverlongJson_IsRefusedBeforeItIsParsed()
    {
        var json = "{\"dnsNames\":[\"" + new string('a', CertificateRequestValidator.MaxPropertiesJsonLength) + "\"]}";
        Assert.False(CertificateRequestValidator.ValidatePropertiesJson(json, out var error));
        Assert.Contains("longer than", error);
    }

    [Fact]
    public void TheAcmeOrderLimit_IsTheSameNumber() =>
        Assert.Equal(100, CertificateRequestValidator.MaxSubjectAlternativeNames);
}
