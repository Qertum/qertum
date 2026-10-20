using Qertum.Services;
using System.Net.Http.Json;
using System.Text.Json;
using Qertum.Cli.Commands;

namespace Qertum.Tests.Aspire;

/// <summary>
/// Covers the external account binding management endpoints, which had no test at all, and
/// deserializes every response through the DTOs <c>qca acme eab</c> actually uses. Parsing with
/// the CLI's own types is the point: a property renamed on the server would otherwise show up as
/// a blank column in the CLI rather than as a failing test.
/// </summary>
[Collection("AspireIntegration")]
public sealed class AcmeExternalAccountKeyTests(AspireIntegrationFixture fixture)
{
    private const string BasePath = "/v1/acme/external-account-keys";

    private static readonly JsonSerializerOptions JsonWeb = new(JsonSerializerDefaults.Web);

    [Fact(DisplayName = "IT-EAB-001")]
    public async Task Create_ReturnsCredentialAndMacKey_InTheShapeTheCliParses()
    {
        var ct = TestContext.Current.CancellationToken;

        var response = await fixture.ApiClientAsAdmin.PostAsJsonAsync(
            BasePath, new { description = "IT-EAB-001 create" }, ct);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var created = JsonSerializer.Deserialize<AcmeExternalAccountKeyCreatedResponse>(
            await response.Content.ReadAsStringAsync(ct), JsonWeb);

        Assert.NotNull(created);
        Assert.NotEqual(Guid.Empty, created.Credential.Id);
        Assert.False(string.IsNullOrWhiteSpace(created.Credential.Kid));
        Assert.Equal("IT-EAB-001 create", created.Credential.Description);
        Assert.True(created.Credential.IsEnabled);
        Assert.Null(created.Credential.BoundAccountId);

        // The MAC key exists only in this response — the CLI prints it with a "shown once"
        // warning, so an empty value here would hand the operator an unusable credential.
        Assert.False(string.IsNullOrWhiteSpace(created.MacKey));

        await fixture.ApiClientAsAdmin.DeleteAsync($"{BasePath}/{created.Credential.Id}", ct);
    }

    [Fact(DisplayName = "IT-EAB-002")]
    public async Task List_NeverCarriesTheMacKey()
    {
        var ct = TestContext.Current.CancellationToken;

        var createResponse = await fixture.ApiClientAsAdmin.PostAsJsonAsync(
            BasePath, new { description = "IT-EAB-002 list" }, ct);
        var created = JsonSerializer.Deserialize<AcmeExternalAccountKeyCreatedResponse>(
            await createResponse.Content.ReadAsStringAsync(ct), JsonWeb)!;

        try
        {
            var listResponse = await fixture.ApiClientAsAdmin.GetAsync(BasePath, ct);
            Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);

            var body = await listResponse.Content.ReadAsStringAsync(ct);

            // The key is projected out of the listing query and never decrypted in bulk. If it
            // ever leaks back in, this is where it shows up.
            Assert.DoesNotContain(created.MacKey, body, StringComparison.Ordinal);

            var keys = JsonSerializer.Deserialize<List<AcmeExternalAccountKeyResponse>>(body, JsonWeb)!;
            var mine = Assert.Single(keys, k => k.Id == created.Credential.Id);
            Assert.Equal(created.Credential.Kid, mine.Kid);
            Assert.Equal("IT-EAB-002 list", mine.Description);
        }
        finally
        {
            await fixture.ApiClientAsAdmin.DeleteAsync($"{BasePath}/{created.Credential.Id}", ct);
        }
    }

    [Fact(DisplayName = "IT-EAB-003")]
    public async Task Disable_AndReEnable_RoundTrip()
    {
        var ct = TestContext.Current.CancellationToken;

        var createResponse = await fixture.ApiClientAsAdmin.PostAsJsonAsync(
            BasePath, new { description = "IT-EAB-003 toggle" }, ct);
        var created = JsonSerializer.Deserialize<AcmeExternalAccountKeyCreatedResponse>(
            await createResponse.Content.ReadAsStringAsync(ct), JsonWeb)!;

        try
        {
            var disableResponse = await fixture.ApiClientAsAdmin.PutAsJsonAsync(
                $"{BasePath}/{created.Credential.Id}", new { isEnabled = false }, ct);
            Assert.Equal(HttpStatusCode.OK, disableResponse.StatusCode);

            var disabled = JsonSerializer.Deserialize<AcmeExternalAccountKeyResponse>(
                await disableResponse.Content.ReadAsStringAsync(ct), JsonWeb)!;
            Assert.False(disabled.IsEnabled);

            var enableResponse = await fixture.ApiClientAsAdmin.PutAsJsonAsync(
                $"{BasePath}/{created.Credential.Id}", new { isEnabled = true }, ct);
            var enabled = JsonSerializer.Deserialize<AcmeExternalAccountKeyResponse>(
                await enableResponse.Content.ReadAsStringAsync(ct), JsonWeb)!;
            Assert.True(enabled.IsEnabled);
        }
        finally
        {
            await fixture.ApiClientAsAdmin.DeleteAsync($"{BasePath}/{created.Credential.Id}", ct);
        }
    }

    [Fact(DisplayName = "IT-EAB-004")]
    public async Task Delete_RemovesTheCredential()
    {
        var ct = TestContext.Current.CancellationToken;

        var createResponse = await fixture.ApiClientAsAdmin.PostAsJsonAsync(
            BasePath, new { description = "IT-EAB-004 delete" }, ct);
        var created = JsonSerializer.Deserialize<AcmeExternalAccountKeyCreatedResponse>(
            await createResponse.Content.ReadAsStringAsync(ct), JsonWeb)!;

        var deleteResponse = await fixture.ApiClientAsAdmin.DeleteAsync(
            $"{BasePath}/{created.Credential.Id}", ct);
        Assert.True(deleteResponse.IsSuccessStatusCode);

        var listResponse = await fixture.ApiClientAsAdmin.GetAsync(BasePath, ct);
        var keys = JsonSerializer.Deserialize<List<AcmeExternalAccountKeyResponse>>(
            await listResponse.Content.ReadAsStringAsync(ct), JsonWeb)!;
        Assert.DoesNotContain(keys, k => k.Id == created.Credential.Id);
    }

    [Fact(DisplayName = "IT-EAB-005")]
    public async Task UnknownId_Is404_SoTheCliCanSaySo()
    {
        var ct = TestContext.Current.CancellationToken;
        var missing = Guid.NewGuid();

        // The CLI turns these into "no external account key with ID ..." rather than dumping a
        // status code, so the 404 has to actually be a 404.
        var update = await fixture.ApiClientAsAdmin.PutAsJsonAsync(
            $"{BasePath}/{missing}", new { isEnabled = false }, ct);
        Assert.Equal(HttpStatusCode.NotFound, update.StatusCode);

        var delete = await fixture.ApiClientAsAdmin.DeleteAsync($"{BasePath}/{missing}", ct);
        Assert.Equal(HttpStatusCode.NotFound, delete.StatusCode);
    }

    [Fact(DisplayName = "IT-EAB-006")]
    public async Task RequiresSettingsEdit()
    {
        var ct = TestContext.Current.CancellationToken;

        // The viewer client holds certificates.view only. Management is settings.edit.
        var list = await fixture.ApiClientAsViewer.GetAsync(BasePath, ct);
        Assert.Equal(HttpStatusCode.Forbidden, list.StatusCode);

        var create = await fixture.ApiClientAsViewer.PostAsJsonAsync(
            BasePath, new { description = "nope" }, ct);
        Assert.Equal(HttpStatusCode.Forbidden, create.StatusCode);
    }
}
