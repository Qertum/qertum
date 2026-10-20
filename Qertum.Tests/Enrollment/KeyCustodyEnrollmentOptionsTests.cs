using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Qertum.Services;
using Qertum.Tests.Policies;

namespace Qertum.Tests.Enrollment;

/// <summary>
/// A policy requiring a client-generated key can only be satisfied by a CSR-carrying request, and
/// <c>CsrPem</c> is pipeline-only — so no REST, wizard or CLI submission can ever satisfy it. The
/// options response therefore hides those templates rather than offering a choice that must fail.
/// </summary>
public sealed class KeyCustodyEnrollmentOptionsTests
{
    private const string Route = "/v1/enrollment/options";

    private static async Task<EnrollmentOptionsResponse> ReadAsync(HttpClient client, CancellationToken ct)
    {
        var response = await client.GetAsync(Route, ct);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<EnrollmentOptionsResponse>(ct))!;
    }

    private static async Task SeedAsync(WebApplicationFactory<ApiServiceProgram> factory,
        KeyCustodyMode custody, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        await PolicySeeding.LinkPublishedPolicyAsync(db, "WebServer", keyCustody: custody, ct: ct);
    }

    [Fact]
    public async Task TemplateRequiringAClientGeneratedKey_IsHiddenFromAnAdmin()
    {
        // Admin bypasses RBAC and the requester-role rule, but cannot conjure a CSR either.
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedAsync(factory, KeyCustodyMode.RequireClientGenerated, ct);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var options = await ReadAsync(client, ct);

        Assert.DoesNotContain(options.Templates, t => t.TypeKey == "WebServer");
        Assert.DoesNotContain(options.Purposes.SelectMany(p => p.TemplateTypeKeys), key => key == "WebServer");
    }

    [Fact]
    public async Task TemplateWithUnrestrictedCustody_IsStillOffered()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedAsync(factory, KeyCustodyMode.Any, ct);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        Assert.Contains((await ReadAsync(client, ct)).Templates, t => t.TypeKey == "WebServer");
    }

    [Fact]
    public async Task OtherTemplates_AreUnaffected()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedAsync(factory, KeyCustodyMode.RequireClientGenerated, ct);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        Assert.Contains((await ReadAsync(client, ct)).Templates, t => t.TypeKey == "ClientAuth");
    }
}
