using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Recovery;

namespace Qertum.Tests.Engineering;

/// <summary>
/// Every ApiService response, success or error, names the request in <c>X-Correlation-Id</c> (the trace
/// id, which the console log also prints), and an error body repeats it as <c>traceId</c>.
/// </summary>
public sealed class CorrelationIdEndpointTests : IDisposable
{
    private static readonly Regex ThirtyTwoHex = new("^[0-9a-f]{32}$");
    private readonly string _dataDirectory = Path.Combine(Path.GetTempPath(), $"correlation-id-{Guid.NewGuid():N}");

    public CorrelationIdEndpointTests() => Directory.CreateDirectory(_dataDirectory);

    public void Dispose()
    {
        try { Directory.Delete(_dataDirectory, recursive: true); } catch { /* best effort */ }
    }

    private sealed class ThrowingRecovery : IRecoveryStatusService
    {
        public Task<RecoveryStatus> GetAsync(CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("the status service blew up");

        public RecoveryStatus Evaluate(CaSettings settings, DateTime nowUtc) => throw new InvalidOperationException();
    }

    private WebApplicationFactory<ApiServiceProgram> CreateFactory(bool throwingRecovery = false)
    {
        var database = SharedInMemoryDatabase.Create();
        return new WebApplicationFactory<ApiServiceProgram>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("ASPNETCORE_ENVIRONMENT", "Test");
            builder.ConfigureTestServices(services =>
            {
                var descriptors = services
                    .Where(d => d.ServiceType == typeof(DbContextOptions<CertificateRequestDbContext>)
                             || d.ServiceType == typeof(CertificateRequestDbContext)
                             || d.ServiceType == typeof(SecretStorageOptions))
                    .ToList();
                foreach (var d in descriptors) services.Remove(d);

                database.ReplaceDbContext(services);
                services.AddSingleton(new SecretStorageOptions { DataDirectory = _dataDirectory });
                if (throwingRecovery)
                    services.AddScoped<IRecoveryStatusService, ThrowingRecovery>();

                services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = "Test";
                    options.DefaultChallengeScheme = "Test";
                }).AddScheme<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions, TestAuthHandler>("Test", _ => { });

                services.AddSingleton(Qertum.Tests.Dashboard.StubCertificateGenerator.Returning(new CaStatusResponse()));
            });
        });
    }

    private static async Task EnsureDbAsync(WebApplicationFactory<ApiServiceProgram> factory, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        await db.Database.OpenConnectionAsync(ct);
        await db.Database.EnsureCreatedAsync(ct);
    }

    private static string CorrelationId(HttpResponseMessage response)
    {
        Assert.True(response.Headers.TryGetValues("X-Correlation-Id", out var values), "X-Correlation-Id header missing");
        return Assert.Single(values);
    }

    private static async Task<string?> BodyTraceIdAsync(HttpResponseMessage response, CancellationToken ct)
    {
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        return document.RootElement.TryGetProperty("traceId", out var id) ? id.GetString() : null;
    }

    [Fact]
    public async Task AnUnauthenticatedCall_StillCarriesTheHeader()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);

        var response = await factory.CreateClient().GetAsync("/v1/recovery-status", ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Matches(ThirtyTwoHex, CorrelationId(response));
    }

    [Fact]
    public async Task AForbiddenCall_CarriesTheHeader()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-NoRole");

        var response = await client.GetAsync("/v1/recovery-status", ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Matches(ThirtyTwoHex, CorrelationId(response));
    }

    [Fact]
    public async Task ASuccessfulCall_CarriesTheHeaderToo()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var response = await client.GetAsync("/v1/recovery-status", ct);

        response.EnsureSuccessStatusCode();
        Assert.Matches(ThirtyTwoHex, CorrelationId(response));
    }

    [Fact]
    public async Task TwoRequests_GetTwoDifferentIds()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var first = CorrelationId(await client.GetAsync("/v1/recovery-status", ct));
        var second = CorrelationId(await client.GetAsync("/v1/recovery-status", ct));

        Assert.NotEqual(first, second);
    }

    [Fact]
    public async Task AnUnhandledException_Is500WithTheSameIdInHeaderAndBody_AndNoStackTrace()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory(throwingRecovery: true);
        await EnsureDbAsync(factory, ct);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var response = await client.GetAsync("/v1/recovery-status", ct);

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        var header = CorrelationId(response);
        Assert.Matches(ThirtyTwoHex, header);
        Assert.Equal(header, await BodyTraceIdAsync(response, ct));
        Assert.DoesNotContain("   at ", await response.Content.ReadAsStringAsync(ct), StringComparison.Ordinal);
    }

    [Fact]
    public async Task AFrameworkBuiltProblem_UsesTheSameBareIdInItsBody()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        var response = await client.GetAsync("/v1/no-such-route", ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(CorrelationId(response), await BodyTraceIdAsync(response, ct));
    }

    [Fact]
    public async Task AnApiProblemFromAHandler_UsesTheSameBareIdInItsBody()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var response = await client.GetAsync($"/v1/certificate-requests/{Guid.NewGuid()}", ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        var header = CorrelationId(response);
        Assert.Matches(ThirtyTwoHex, header);
        Assert.Equal(header, await BodyTraceIdAsync(response, ct));
    }

    [Fact]
    public async Task AValidationProblem_UsesTheSameBareIdInItsBody()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var response = await client.PostAsync("/v1/certificate-requests",
            new StringContent("{}", System.Text.Encoding.UTF8, "application/json"), ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(CorrelationId(response), await BodyTraceIdAsync(response, ct));
    }
}
