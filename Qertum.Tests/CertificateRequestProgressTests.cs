using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Http;
using Qertum.Services;

namespace Qertum.Tests;

/// <summary>
/// One definition of "in progress" and "final", and the server's polling hint: while a request is on its way to a
/// final state the API says "retry in 2 seconds", and says nothing once it is there (or while it waits for a human).
/// </summary>
public sealed class CertificateRequestProgressTests
{
    [Theory]
    [InlineData(CertificateRequestStatus.Pending, false, false)]
    [InlineData(CertificateRequestStatus.Approved, true, false)]
    [InlineData(CertificateRequestStatus.Processing, true, false)]
    [InlineData(CertificateRequestStatus.PendingRevocation, true, false)]
    [InlineData(CertificateRequestStatus.Issued, false, true)]
    [InlineData(CertificateRequestStatus.Rejected, false, true)]
    [InlineData(CertificateRequestStatus.Revoked, false, true)]
    public void EveryStatus_IsInProgress_Final_OrWaitingForAHuman(CertificateRequestStatus status, bool inProgress, bool final)
    {
        Assert.Equal(inProgress, status.IsInProgress());
        Assert.Equal(final, status.IsFinal());
    }

    [Fact]
    public void NoStatusIsBothInProgressAndFinal_AndEveryStatusIsCovered()
    {
        foreach (var status in Enum.GetValues<CertificateRequestStatus>())
            Assert.False(status.IsInProgress() && status.IsFinal(), status.ToString());

        // A new status must be placed on purpose: this fails until the helpers (and the theory above) know it.
        Assert.Equal(7, Enum.GetValues<CertificateRequestStatus>().Length);
    }

    [Theory]
    [InlineData(CertificateRequestStatus.Approved, "2")]
    [InlineData(CertificateRequestStatus.Processing, "2")]
    [InlineData(CertificateRequestStatus.PendingRevocation, "2")]
    [InlineData(CertificateRequestStatus.Pending, null)]
    [InlineData(CertificateRequestStatus.Issued, null)]
    [InlineData(CertificateRequestStatus.Rejected, null)]
    [InlineData(CertificateRequestStatus.Revoked, null)]
    public void ApplyingTheHint_SetsRetryAfterOnlyWhileInProgress(CertificateRequestStatus status, string? expected)
    {
        var context = new DefaultHttpContext();

        ProgressHints.Apply(context.Response, status);

        Assert.Equal(expected, context.Response.Headers.RetryAfter.ToString() is { Length: > 0 } value ? value : null);
    }

    [Fact]
    public async Task OverTheApi_ARequestGetsTheHintOnlyOnceApproved()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var created = await (await client.PostAsJsonAsync("/v1/certificate-requests",
            new { CommonName = "progress.local", RequestedBy = "tester", Type = "WebServer", PropertiesJson = "{}" }, ct))
            .Content.ReadFromJsonAsync<CertificateRequest>(ct);
        Assert.NotNull(created);
        var url = $"/v1/certificate-requests/{created.Id}";

        var pending = await client.GetAsync(url, ct);
        Assert.False(pending.Headers.Contains("Retry-After"));

        var approve = await client.PostAsync(url + "/approve", null, ct);
        Assert.Equal(HttpStatusCode.OK, approve.StatusCode);
        Assert.Equal("2", Assert.Single(approve.Headers.GetValues("Retry-After")));

        // The queue consumer is not running in this host, so the request stays Approved: still in progress.
        var approved = await client.GetAsync(url, ct);
        Assert.Equal("2", Assert.Single(approved.Headers.GetValues("Retry-After")));
    }
}
