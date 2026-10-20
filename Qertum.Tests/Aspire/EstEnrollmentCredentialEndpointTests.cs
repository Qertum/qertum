using System.Net.Http.Json;
using System.Text.Json;
using Qertum.Cli.Commands;
using Qertum.Services;

namespace Qertum.Tests.Aspire;

/// <summary>
/// Covers the EST enrollment credential management endpoints
/// (<c>/v1/est/enrollment-credentials</c>), mirroring <see cref="AcmeExternalAccountKeyTests"/>.
/// Deserializes every response through the DTOs <c>qca est credentials</c> actually uses. Parsing with
/// the CLI's own types is the point: a property renamed on the server would otherwise show up as
/// a blank column in the CLI rather than as a failing test.
/// </summary>
[Collection("AspireIntegration")]
public sealed class EstEnrollmentCredentialEndpointTests(AspireIntegrationFixture fixture)
{
    private const string BasePath = "/v1/est/enrollment-credentials";

    private static readonly JsonSerializerOptions JsonWeb = new(JsonSerializerDefaults.Web);

    [Fact(DisplayName = "IT-EST-CRED-001")]
    public async Task Create_returns_the_password_once()
    {
        var ct = TestContext.Current.CancellationToken;

        var response = await fixture.ApiClientAsAdmin.PostAsJsonAsync(
            BasePath,
            new { username = "it-est-cred-001", password = "S0meStrongPassw0rd!", description = "IT-EST-CRED-001 create" },
            ct);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var created = JsonSerializer.Deserialize<EstEnrollmentCredentialCreatedResponse>(
            await response.Content.ReadAsStringAsync(ct), JsonWeb);

        Assert.NotNull(created);
        Assert.NotEqual(Guid.Empty, created.Credential.Id);
        Assert.Equal("it-est-cred-001", created.Credential.Username);
        Assert.Equal("IT-EST-CRED-001 create", created.Credential.Description);
        Assert.True(created.Credential.IsEnabled);

        // The password exists only in this response — nothing reads it back afterwards.
        // Unlike ACME's server-generated MAC key, the EST password is client-supplied,
        // so exact-match verification catches truncation/mangling.
        Assert.Equal("S0meStrongPassw0rd!", created.Password);

        await fixture.ApiClientAsAdmin.DeleteAsync($"{BasePath}/{created.Credential.Id}", ct);
    }

    [Fact(DisplayName = "IT-EST-CRED-002")]
    public async Task List_never_returns_the_password_or_its_hash()
    {
        var ct = TestContext.Current.CancellationToken;

        var createResponse = await fixture.ApiClientAsAdmin.PostAsJsonAsync(
            BasePath,
            new { username = "it-est-cred-002", password = "An0therStrongPassw0rd!", description = "IT-EST-CRED-002 list" },
            ct);
        var created = JsonSerializer.Deserialize<EstEnrollmentCredentialCreatedResponse>(
            await createResponse.Content.ReadAsStringAsync(ct), JsonWeb)!;

        try
        {
            var listResponse = await fixture.ApiClientAsAdmin.GetAsync(BasePath, ct);
            Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);

            var body = await listResponse.Content.ReadAsStringAsync(ct);

            // Neither the plaintext password nor the hash should ever appear in the listing.
            Assert.DoesNotContain("password", body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("passwordHash", body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(created.Password, body, StringComparison.Ordinal);

            var items = JsonSerializer.Deserialize<List<EstEnrollmentCredentialResponse>>(body, JsonWeb)!;
            var mine = Assert.Single(items, k => k.Id == created.Credential.Id);
            Assert.Equal("it-est-cred-002", mine.Username);
            Assert.Equal("IT-EST-CRED-002 list", mine.Description);
        }
        finally
        {
            await fixture.ApiClientAsAdmin.DeleteAsync($"{BasePath}/{created.Credential.Id}", ct);
        }
    }

    [Fact(DisplayName = "IT-EST-CRED-003")]
    public async Task Disable_AndReEnable_RoundTrip()
    {
        var ct = TestContext.Current.CancellationToken;

        var createResponse = await fixture.ApiClientAsAdmin.PostAsJsonAsync(
            BasePath,
            new { username = "it-est-cred-003", password = "YetAnotherStrongPassw0rd!", description = "IT-EST-CRED-003 toggle" },
            ct);
        var created = JsonSerializer.Deserialize<EstEnrollmentCredentialCreatedResponse>(
            await createResponse.Content.ReadAsStringAsync(ct), JsonWeb)!;

        try
        {
            var disableResponse = await fixture.ApiClientAsAdmin.PutAsJsonAsync(
                $"{BasePath}/{created.Credential.Id}", new { isEnabled = false }, ct);
            Assert.Equal(HttpStatusCode.OK, disableResponse.StatusCode);

            var disabled = JsonSerializer.Deserialize<EstEnrollmentCredentialResponse>(
                await disableResponse.Content.ReadAsStringAsync(ct), JsonWeb)!;
            Assert.False(disabled.IsEnabled);

            var enableResponse = await fixture.ApiClientAsAdmin.PutAsJsonAsync(
                $"{BasePath}/{created.Credential.Id}", new { isEnabled = true }, ct);
            var enabled = JsonSerializer.Deserialize<EstEnrollmentCredentialResponse>(
                await enableResponse.Content.ReadAsStringAsync(ct), JsonWeb)!;
            Assert.True(enabled.IsEnabled);
        }
        finally
        {
            await fixture.ApiClientAsAdmin.DeleteAsync($"{BasePath}/{created.Credential.Id}", ct);
        }
    }

    [Fact(DisplayName = "IT-EST-CRED-004")]
    public async Task Delete_RemovesTheCredential()
    {
        var ct = TestContext.Current.CancellationToken;

        var createResponse = await fixture.ApiClientAsAdmin.PostAsJsonAsync(
            BasePath,
            new { username = "it-est-cred-004", password = "OneMoreStrongPassw0rd!", description = "IT-EST-CRED-004 delete" },
            ct);
        var created = JsonSerializer.Deserialize<EstEnrollmentCredentialCreatedResponse>(
            await createResponse.Content.ReadAsStringAsync(ct), JsonWeb)!;

        var deleteResponse = await fixture.ApiClientAsAdmin.DeleteAsync(
            $"{BasePath}/{created.Credential.Id}", ct);
        Assert.True(deleteResponse.IsSuccessStatusCode);

        var listResponse = await fixture.ApiClientAsAdmin.GetAsync(BasePath, ct);
        var items = JsonSerializer.Deserialize<List<EstEnrollmentCredentialResponse>>(
            await listResponse.Content.ReadAsStringAsync(ct), JsonWeb)!;
        Assert.DoesNotContain(items, k => k.Id == created.Credential.Id);
    }

    [Fact(DisplayName = "IT-EST-CRED-005")]
    public async Task UnknownId_Is404()
    {
        var ct = TestContext.Current.CancellationToken;
        var missing = Guid.NewGuid();

        var update = await fixture.ApiClientAsAdmin.PutAsJsonAsync(
            $"{BasePath}/{missing}", new { isEnabled = false }, ct);
        Assert.Equal(HttpStatusCode.NotFound, update.StatusCode);

        var delete = await fixture.ApiClientAsAdmin.DeleteAsync($"{BasePath}/{missing}", ct);
        Assert.Equal(HttpStatusCode.NotFound, delete.StatusCode);
    }

    [Fact(DisplayName = "IT-EST-CRED-006")]
    public async Task RequiresSettingsEdit()
    {
        var ct = TestContext.Current.CancellationToken;

        // The viewer client holds certificates.view only. Management is settings.edit.
        var list = await fixture.ApiClientAsViewer.GetAsync(BasePath, ct);
        Assert.Equal(HttpStatusCode.Forbidden, list.StatusCode);

        var create = await fixture.ApiClientAsViewer.PostAsJsonAsync(
            BasePath, new { username = "nope", password = "nope", description = "nope" }, ct);
        Assert.Equal(HttpStatusCode.Forbidden, create.StatusCode);
    }
}
