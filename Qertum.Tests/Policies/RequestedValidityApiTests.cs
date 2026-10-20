using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.Policies;

/// <summary>
/// A request may ask for a shorter validity than its template's default. Asking for a longer one
/// needs an issuance policy whose maximum allows it.
/// </summary>
public sealed class RequestedValidityApiTests
{
    private static HttpClient Admin(WebApplicationFactory<ApiServiceProgram> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        return client;
    }

    private static Task<HttpResponseMessage> CreateAsync(HttpClient client, string commonName, int? validityDays, CancellationToken ct) =>
        client.PostAsJsonAsync("/v1/certificate-requests",
            new { CommonName = commonName, Type = "WebServer", PropertiesJson = "{}", ValidityDays = validityDays }, ct);

    [Fact]
    public async Task ShorterValidity_IsStoredOnTheRequest()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var response = await CreateAsync(admin, "short.example.com", 30, ct);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var scope = factory.Services.CreateScope();
        var row = await scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>()
            .CertificateRequests.AsNoTracking().SingleAsync(r => r.CommonName == "short.example.com", ct);
        Assert.Equal(30, row.ValidityDays);
    }

    [Fact]
    public async Task LongerThanTheTemplateDefault_IsRejected()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var response = await CreateAsync(admin, "long.example.com", 4000, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var scope = factory.Services.CreateScope();
        Assert.False(await scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>()
            .CertificateRequests.AnyAsync(r => r.CommonName == "long.example.com", ct));
    }

    [Fact]
    public async Task LongerThanTheDefault_IsAllowedWhenAPolicyRaisesTheCeiling()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            await PolicySeeding.LinkPublishedPolicyAsync(db, "WebServer", maxValidityDays: 1000, ct: ct);
        }
        using var admin = Admin(factory);

        var response = await CreateAsync(admin, "ceiling.example.com", 900, ct);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task ZeroOrNegativeValidity_FailsValidation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var response = await CreateAsync(admin, "zero.example.com", 0, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
