using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Qertum.Cli.Commands;
using Qertum.Services;

namespace Qertum.Tests.Policies;

/// <summary>
/// Parses real policy API responses through the DTOs <c>qca policies</c> prints from. A property
/// renamed on the server would otherwise surface as a blank column in the CLI rather than a failure.
/// </summary>
public sealed class PolicyCliContractTests
{
    private static readonly JsonSerializerOptions JsonWeb = new(JsonSerializerDefaults.Web);

    private static HttpClient Admin(WebApplicationFactory<ApiServiceProgram> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        return client;
    }

    [Fact]
    public async Task ListShowAndVersions_ParseThroughTheCliDtos()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var created = await admin.PostAsJsonAsync("/v1/issuance-policies",
            new { name = "cli-contract", description = "parsed by the CLI" }, ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var policy = JsonSerializer.Deserialize<IssuancePolicyResponse>(
            await created.Content.ReadAsStringAsync(ct), JsonWeb)!;
        Assert.Equal("cli-contract", policy.Name);

        var draftSaved = await admin.PutAsJsonAsync($"/v1/issuance-policies/{policy.Id}/draft", new
        {
            allowedDnsSuffixes = new[] { "corp.example.com" },
            allowedIpRanges = Array.Empty<string>(),
            allowedKeyAlgorithms = new[] { "ECDSA-P256" },
            maxValidityDays = 200
        }, ct);
        Assert.Equal(HttpStatusCode.OK, draftSaved.StatusCode);
        var withDraft = JsonSerializer.Deserialize<IssuancePolicyResponse>(
            await draftSaved.Content.ReadAsStringAsync(ct), JsonWeb)!;
        Assert.NotNull(withDraft.Draft);
        Assert.Equal(["corp.example.com"], withDraft.Draft.AllowedDnsSuffixes);
        Assert.Equal(["ECDSA-P256"], withDraft.Draft.AllowedKeyAlgorithms);
        Assert.Equal(200, withDraft.Draft.MaxValidityDays);

        // The publish token the CLI sends is read straight off the draft it printed.
        var published = await admin.PostAsJsonAsync($"/v1/issuance-policies/{policy.Id}/publish",
            new { draftVersionId = withDraft.Draft.Id, draftUpdatedAtUtc = withDraft.Draft.UpdatedAtUtc }, ct);
        Assert.Equal(HttpStatusCode.OK, published.StatusCode);
        var enforced = JsonSerializer.Deserialize<IssuancePolicyResponse>(
            await published.Content.ReadAsStringAsync(ct), JsonWeb)!;
        Assert.Equal(1, enforced.Published!.VersionNumber);
        Assert.Equal(IssuancePolicyVersionStatus.Published, enforced.Published.Status);

        var list = JsonSerializer.Deserialize<List<IssuancePolicySummaryResponse>>(
            await admin.GetStringAsync("/v1/issuance-policies", ct), JsonWeb)!;
        var summary = Assert.Single(list, p => p.Id == policy.Id);
        Assert.Equal(1, summary.PublishedVersionNumber);
        Assert.False(summary.HasDraft);
        Assert.Equal(0, summary.LinkedTemplateCount);

        var versions = JsonSerializer.Deserialize<List<IssuancePolicyVersionResponse>>(
            await admin.GetStringAsync($"/v1/issuance-policies/{policy.Id}/versions", ct), JsonWeb)!;
        Assert.Equal(1, Assert.Single(versions).VersionNumber);
    }

    [Fact]
    public async Task AViolationResponse_CarriesTheRulesTheCliPrints()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            await PolicySeeding.LinkPublishedPolicyAsync(db, "WebServer", dnsSuffixes: ["corp.example.com"], ct: ct);
        }
        using var admin = Admin(factory);

        var response = await admin.PostAsJsonAsync("/v1/certificate-requests",
            new { CommonName = "host.other.net", Type = "WebServer", PropertiesJson = "{}" }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        Assert.Equal("Issuance Policy Violation", problem.RootElement.GetProperty("title").GetString());
        var violations = problem.RootElement.GetProperty("violations");
        Assert.True(violations.GetArrayLength() > 0);
        Assert.Contains("host.other.net", violations[0].GetProperty("message").GetString());
    }
}
