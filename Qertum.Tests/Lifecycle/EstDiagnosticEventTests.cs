using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Qertum.Services.Lifecycle;

namespace Qertum.Tests.Lifecycle;

/// <summary>
/// Recording why EST refused a device must not change what the device sees: every Basic-auth failure
/// stays the identical 401, and an unknown username is not recorded at all.
/// </summary>
public sealed class EstDiagnosticEventTests : IClassFixture<EstTestFactory>
{
    private readonly EstTestFactory _factory;

    public EstDiagnosticEventTests(EstTestFactory factory) => _factory = factory;

    [Fact]
    public async Task AWrongPassword_Is401LikeAnyOther_AndIsRecordedAgainstTheCredential()
    {
        var ct = TestContext.Current.CancellationToken;
        var credentialId = await _factory.SeedCredentialAsync("diag-device", "right-password", ct);

        var wrong = await EnrollAsync("diag-device", "wrong-password", ct);
        var unknown = await EnrollAsync("no-such-device", "whatever", ct);

        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(wrong.Headers.WwwAuthenticate.ToString(), unknown.Headers.WwwAuthenticate.ToString());
        Assert.Equal(await wrong.Content.ReadAsStringAsync(ct), await unknown.Content.ReadAsStringAsync(ct));

        var refused = Assert.Single(_factory.Diagnostics.Entries,
            e => e.SubjectId == credentialId && e.Action == DiagnosticActions.AuthRefused);
        Assert.Equal(DiagnosticCategories.WrongPassword, refused.Category);
        Assert.DoesNotContain(_factory.Diagnostics.Entries,
            e => (e.Detail ?? "").Contains("no-such-device", StringComparison.Ordinal)
                 || (e.Detail ?? "").Contains("wrong-password", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnUnparseableCsr_IsRecordedAsAnEnrollmentRefusal()
    {
        var ct = TestContext.Current.CancellationToken;
        var credentialId = await _factory.SeedCredentialAsync("diag-csr", "pw-123456", ct);

        var response = await EnrollAsync("diag-csr", "pw-123456", ct, body: "not a csr");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var refused = Assert.Single(_factory.Diagnostics.Entries,
            e => e.SubjectId == credentialId && e.Action == DiagnosticActions.EnrollmentRefused);
        Assert.Equal(DiagnosticCategories.UnparseableCsr, refused.Category);
    }

    private async Task<HttpResponseMessage> EnrollAsync(string user, string password, CancellationToken ct, string body = "MIIB")
    {
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{password}")));
        return await client.PostAsync("/.well-known/est/simpleenroll",
            new StringContent(body, Encoding.ASCII, "application/pkcs10"), ct);
    }
}
