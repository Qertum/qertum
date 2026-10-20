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
}
