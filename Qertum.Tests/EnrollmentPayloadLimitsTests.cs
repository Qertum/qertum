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
}
