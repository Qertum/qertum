using Qertum.Services.Est;
using Xunit;

namespace Qertum.Tests;

public class EstCsrHelperTests
{
    [Fact]
    public void ExtractIdentity_reads_common_name_and_dns_sans()
    {
        var csrBase64Url = TestCsrBuilder.BuildBase64Url(
            subjectCn: "device1.example.com",
            sanDnsNames: ["device1.example.com", "device1-alt.example.com"]);

        var (commonName, dnsNames) = EstCsrHelper.ExtractIdentity(csrBase64Url);

        Assert.Equal("device1.example.com", commonName);
        Assert.Equal(["device1.example.com", "device1-alt.example.com"], dnsNames);
    }

    [Fact]
    public void ExtractIdentity_returns_empty_dns_names_when_no_san_present()
    {
        var csrBase64Url = TestCsrBuilder.BuildBase64Url(subjectCn: "device2.example.com", sanDnsNames: []);

        var (commonName, dnsNames) = EstCsrHelper.ExtractIdentity(csrBase64Url);

        Assert.Equal("device2.example.com", commonName);
        Assert.Empty(dnsNames);
    }

    [Fact]
    public void ExtractIdentity_refuses_more_dns_names_than_a_request_may_carry()
    {
        // Same bound as REST and ACME (AI Scan, rc7): every name is stored, evaluated and encoded.
        var names = Enumerable.Range(0, 101).Select(i => $"d{i}.example.com").ToArray();
        var refused = TestCsrBuilder.BuildBase64Url(subjectCn: "d0.example.com", sanDnsNames: names);
        var accepted = TestCsrBuilder.BuildBase64Url(subjectCn: "d0.example.com", sanDnsNames: names[..100]);

        Assert.Contains("more than 100", Assert.Throws<ArgumentException>(() => EstCsrHelper.ExtractIdentity(refused)).Message);
        Assert.Equal(100, EstCsrHelper.ExtractIdentity(accepted).DnsNames.Count);
    }
}
