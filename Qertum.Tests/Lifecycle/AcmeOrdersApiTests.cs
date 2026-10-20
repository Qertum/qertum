using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Services.Acme;
using Qertum.Services.Lifecycle;

namespace Qertum.Tests.Lifecycle;

/// <summary>
/// The orders routes, read through the same typed client the Web pages and <c>qca acme orders</c> use,
/// so a contract drift between server and client fails here.
/// </summary>
public sealed class AcmeOrdersApiTests
{
    [Fact]
    public async Task TheTypedClient_ReadsRealOrderResponses()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        var orderId = await SeedOrderAsync(factory, ct);
        var client = Client(factory, "Test");

        var page = await client.GetAcmeOrdersAsync(null, failingOnly: true, 1, 50, ct);
        var detail = await client.GetAcmeOrderAsync(orderId, ct);

        var item = Assert.Single(page.Items);
        Assert.Equal(["cli.example.com"], item.Identifiers);
        Assert.Equal("HttpStatus", item.LastFailureCategory);
        Assert.Equal("http-01", Assert.Single(Assert.Single(detail!.Authorizations).Challenges).Type);
        var entry = Assert.Single(detail.History);
        Assert.Equal(TimelineEntryKind.Diagnostic, entry.Kind);
        Assert.Equal(DiagnosticHints.For("HttpStatus"), entry.Hint);
    }

    [Fact]
    public async Task AnUnknownOrder_IsNull_AndWithoutSettingsEdit_Is403()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            db.RolePermissions.Add(new RolePermission { Role = "viewer", Permission = AppPermissions.CertificatesView });
            await db.SaveChangesAsync(ct);
        }

        Assert.Null(await Client(factory, "Test").GetAcmeOrderAsync(Guid.NewGuid(), ct));
        var refused = await Assert.ThrowsAsync<ApiProblemException>(() =>
            Client(factory, "Test-Role", "viewer").GetAcmeOrdersAsync(null, false, 1, 50, ct));
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
    }

    private static CertificateRequestsApiClient Client(
        Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<ApiServiceProgram> factory, string scheme, string? parameter = null)
    {
        var http = factory.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(scheme, parameter);
        return new CertificateRequestsApiClient(http);
    }

    private static async Task<Guid> SeedOrderAsync(
        Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<ApiServiceProgram> factory, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var account = new AcmeAccount { JwkThumbprint = "t", PublicKeyJwk = "{}" };
        var order = new AcmeOrder
        {
            AccountId = account.Id, IdentifiersJson = """[{"type":"dns","value":"cli.example.com"}]""",
            ExpiresAtUtc = DateTime.UtcNow.AddDays(7)
        };
        var auth = new AcmeAuthorization { OrderId = order.Id, IdentifierValue = "cli.example.com", ExpiresAtUtc = DateTime.UtcNow.AddDays(7) };
        db.AcmeAccounts.Add(account);
        db.AcmeOrders.Add(order);
        db.AcmeAuthorizations.Add(auth);
        db.AcmeChallenges.Add(new AcmeChallenge { AuthorizationId = auth.Id, Type = "http-01", Token = "tok", Status = "processing", ValidationAttempts = 1 });
        db.LifecycleEvents.Add(new LifecycleEvent
        {
            Id = Guid.NewGuid(), Kind = LifecycleEventKinds.Diagnostic, OccurredAtUtc = DateTime.UtcNow,
            SubjectType = LifecycleSubjectTypes.AcmeOrder, SubjectId = order.Id,
            Action = DiagnosticActions.ChallengeAttemptFailed, Category = "HttpStatus", Detail = "HTTP 404", PerformedBy = "system"
        });
        await db.SaveChangesAsync(ct);
        return order.Id;
    }
}
