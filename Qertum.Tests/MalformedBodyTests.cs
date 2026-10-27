using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Qertum.Tests.Issuers;

namespace Qertum.Tests;

/// <summary>
/// A request body the framework cannot read (broken JSON, an enum name that does not exist, the wrong type) is the
/// caller's mistake: 400 with a problem body and the correlation id, never a 500 that looks like a server fault.
/// </summary>
public sealed class MalformedBodyTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("/v1/settings/revoked-issuer", "{\"mode\":\"Nope\"}")]
    [InlineData("/v1/settings/issuer-strength", "{\"mode\":\"Nope\"}")]
    [InlineData("/v1/settings/revoked-issuer", "{\"mode\":")]
    [InlineData("/v1/settings/revoked-issuer", "{\"mode\":[1]}")]
    public async Task AnUnreadableBody_Is400WithAProblemBody(string path, string json)
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy("Root");

        var response = await host.Admin().PutAsync(path, new StringContent(json, Encoding.UTF8, "application/json"), Ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Ct));
        Assert.Equal("Bad Request", body.RootElement.GetProperty("title").GetString());
        Assert.True(body.RootElement.TryGetProperty("traceId", out _));
    }
}
