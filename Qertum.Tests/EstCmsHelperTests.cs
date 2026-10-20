using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Qertum.Services.Est;
using Xunit;

namespace Qertum.Tests;

public class EstCmsHelperTests
{
    [Fact]
    public void BuildDegenerateCmsBase64_round_trips_a_single_certificate()
    {
        using var cert = TestCertificates.CreateSelfSigned("CN=est-test");

        var base64 = EstCmsHelper.BuildDegenerateCmsBase64([cert]);
        var parsed = EstCmsHelper.ParseDegenerateCms(base64);

        Assert.Single(parsed);
        Assert.Equal(cert.Thumbprint, parsed[0].Thumbprint);
    }

    [Fact]
    public void BuildDegenerateCmsBase64_round_trips_a_chain()
    {
        using var root = TestCertificates.CreateSelfSigned("CN=est-root");
        using var leaf = TestCertificates.CreateSelfSigned("CN=est-leaf");

        var base64 = EstCmsHelper.BuildDegenerateCmsBase64([leaf, root]);
        var parsed = EstCmsHelper.ParseDegenerateCms(base64);

        // The PKCS#7 `certificates` field is an ASN.1 SET, not a SEQUENCE, so BouncyCastle's
        // enumeration order is not a guaranteed property of the wire format — assert presence
        // by identity, not position.
        Assert.Equal(2, parsed.Count);
        var thumbprints = parsed.Select(c => c.Thumbprint);
        Assert.Contains(leaf.Thumbprint, thumbprints);
        Assert.Contains(root.Thumbprint, thumbprints);
    }
}
