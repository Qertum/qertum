using System.Text;
using Microsoft.AspNetCore.Http;
using Qertum.Services;

namespace Qertum.Tests;

public sealed class EnrollmentPayloadLimitsTests
{
    [Fact]
    public async Task UnknownContentLength_IsBoundedWhileReading()
    {
        var request = new DefaultHttpContext().Request;
        request.Body = new MemoryStream(new byte[129]);
        request.ContentLength = null;

        await Assert.ThrowsAsync<EnrollmentPayloadTooLargeException>(() =>
            EnrollmentPayloadLimits.ReadUtf8Async(request, 128, TestContext.Current.CancellationToken));
        Assert.Equal(129, request.Body.Position);
    }

    [Fact]
    public async Task ExactBodyLimit_IsAccepted()
    {
        var request = new DefaultHttpContext().Request;
        request.Body = new MemoryStream(Encoding.UTF8.GetBytes(new string('x', 128)));

        var body = await EnrollmentPayloadLimits.ReadUtf8Async(request, 128, TestContext.Current.CancellationToken);

        Assert.Equal(128, body.Length);
    }

    [Fact]
    public void ExactDecodedLimit_IsAccepted()
    {
        var encoded = Convert.ToBase64String(new byte[64]);

        Assert.Equal(64, EnrollmentPayloadLimits.DecodeBase64(encoded, 64).Length);
        Assert.Throws<EnrollmentPayloadTooLargeException>(() =>
            EnrollmentPayloadLimits.DecodeBase64(Convert.ToBase64String(new byte[65]), 64));
    }

    // The CSR of an SLH-DSA-SHA2-256F key (a 49,999-byte signature) is the largest the CA issues from: about 50,000 bytes.
    private const int LargestCsrBytes = 50_000;

    private static int Base64Length(int bytes) => (bytes + 2) / 3 * 4;

    [Fact]
    public void AcmeLimits_AdmitTheLargestCsrInAFinalizeRequest()
    {
        const int envelope = 9; // {"csr":""}
        Assert.True(LargestCsrBytes <= EnrollmentPayloadLimits.CsrBytes);
        Assert.True(Base64Length(EnrollmentPayloadLimits.CsrBytes) + envelope <= EnrollmentPayloadLimits.DecodedPayloadBytes,
            "a CsrBytes-sized CSR in base64url must fit the decoded payload limit");
        Assert.True(Base64Length(EnrollmentPayloadLimits.DecodedPayloadBytes) + 4096 <= EnrollmentPayloadLimits.AcmeBodyBytes,
            "a payload at its limit, base64url-encoded again, plus header and signature must fit the body limit");
    }

    [Fact]
    public void EstLimit_AdmitsTheLargestCsrAsFoldedBase64()
    {
        // RFC 2045 folding adds a line break per 76 characters.
        var folded = Base64Length(EnrollmentPayloadLimits.CsrBytes) * 78 / 76;
        Assert.True(folded <= EnrollmentPayloadLimits.EstBodyBytes);
    }
}
