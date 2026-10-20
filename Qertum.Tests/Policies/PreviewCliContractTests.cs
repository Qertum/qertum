using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Qertum.Cli.Commands;
using Qertum.Services;

namespace Qertum.Tests.Policies;

/// <summary>
/// Parses a real preview response through the DTO <c>qca requests create --dry-run</c> prints from,
/// so a property renamed on the server fails here rather than blanking a column.
/// </summary>
public sealed class PreviewCliContractTests
{
    [Fact]
    public async Task CliPreviewDto_ParsesARealPreviewResponse()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var response = await client.PostAsJsonAsync("/v1/certificate-requests/preview", new
        {
            commonName = "cli-preview.example.com",
            type = "WebServer",
            propertiesJson = "{}"
        }, ct);
        var body = await response.Content.ReadAsStringAsync(ct);

        var parsed = JsonSerializer.Deserialize<CertificateRequestPreviewResponse>(
            body, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.NotNull(parsed);
        Assert.True(parsed!.Allowed);
        Assert.Equal("WebServer", parsed.TemplateTypeKey);
        Assert.Equal("RSA", parsed.EffectiveKeyAlgorithm);
        Assert.True(parsed.EffectiveValidityDays > 0);
    }

    [Fact]
    public async Task CliPreviewDto_CarriesTheViolationsOfARejection()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            await PolicySeeding.LinkPublishedPolicyAsync(db, "WebServer", dnsSuffixes: ["corp.example.com"], ct: ct);
        }

        var response = await client.PostAsJsonAsync("/v1/certificate-requests/preview", new
        {
            commonName = "cli-rejected.other.net",
            type = "WebServer",
            propertiesJson = "{}"
        }, ct);
        var body = await response.Content.ReadAsStringAsync(ct);

        var parsed = JsonSerializer.Deserialize<CertificateRequestPreviewResponse>(
            body, new JsonSerializerOptions(JsonSerializerDefaults.Web))!;

        Assert.False(parsed.Allowed);
        Assert.NotEmpty(parsed.Violations);
        Assert.All(parsed.Violations, v => Assert.False(string.IsNullOrWhiteSpace(v.Message)));
        Assert.All(parsed.Violations, v => Assert.False(string.IsNullOrWhiteSpace(v.Rule)));
    }
}
