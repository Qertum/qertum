using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;

namespace Qertum.Tests.Engineering;

/// <summary>
/// Every REST error is RFC 9457 problem details. The API used to answer in four shapes (problem
/// details, a bare string, an anonymous <c>{ error }</c> object and an empty body), so a client could
/// not read an error without knowing which route produced it. ACME, EST, /crl and /ocsp keep the
/// formats their protocols define and are not covered here.
/// </summary>
public sealed partial class ProblemDetailsTests
{
    [Fact]
    public async Task AMissingResource_IsAProblem()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);

        var response = await Admin(factory).GetAsync($"/v1/certificate-requests/{Guid.NewGuid()}", ct);

        await AssertProblemAsync(response, HttpStatusCode.NotFound, ct);
    }

    [Fact]
    public async Task AnIllegalTransition_IsAProblemWithTheReasonAsDetail()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        Guid id;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            var request = new CertificateRequest
            {
                CommonName = "issued.example.com", RequestedBy = "alice", Type = "WebServer",
                Status = CertificateRequestStatus.Issued, CreatedAtUtc = DateTime.UtcNow, UpdatedAtUtc = DateTime.UtcNow
            };
            db.CertificateRequests.Add(request);
            await db.SaveChangesAsync(ct);
            id = request.Id;
        }

        var response = await Admin(factory).PostAsync($"/v1/certificate-requests/{id}/approve", null, ct);

        var problem = await AssertProblemAsync(response, HttpStatusCode.Conflict, ct);
        Assert.Contains("Cannot approve", problem.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task AnUnauthenticatedCall_IsAProblem()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);

        var response = await factory.CreateClient().GetAsync("/v1/settings", ct);

        await AssertProblemAsync(response, HttpStatusCode.Unauthorized, ct);
    }

    [Fact]
    public async Task AnUnknownRoute_IsAProblem()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);

        var response = await Admin(factory).GetAsync("/v1/no-such-route", ct);

        await AssertProblemAsync(response, HttpStatusCode.NotFound, ct);
    }

    [Theory]
    [InlineData("Qertum.Services/ApiEndpointMappings.cs")]
    [InlineData("Qertum.Services/IssuancePolicyEndpointMappings.cs")]
    public void RestMappings_AnswerErrorsOnlyAsProblems(string file)
    {
        var path = Path.Combine(FindRepoRoot(), file);
        var offenders = File.ReadLines(path)
            .Select((line, i) => (Line: i + 1, Text: line))
            .Where(l => NonProblemError().IsMatch(l.Text))
            .Select(l => $"{file}:{l.Line}: {l.Text.Trim()}")
            .ToList();

        Assert.True(offenders.Count == 0, "Answer errors through ApiProblem:\n" + string.Join('\n', offenders));
    }

    private static HttpClient Admin(Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<ApiServiceProgram> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        return client;
    }

    private static async Task<JsonElement> AssertProblemAsync(HttpResponseMessage response, HttpStatusCode status, CancellationToken ct)
    {
        Assert.Equal(status, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct)).RootElement;
        Assert.Equal((int)status, problem.GetProperty("status").GetInt32());
        Assert.False(string.IsNullOrWhiteSpace(problem.GetProperty("title").GetString()));
        return problem;
    }

    [GeneratedRegex(@"Results\.(NotFound|BadRequest|Conflict|UnprocessableEntity)\(")]
    private static partial Regex NonProblemError();

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Qertum.sln")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Qertum.sln not found.");
    }
}
