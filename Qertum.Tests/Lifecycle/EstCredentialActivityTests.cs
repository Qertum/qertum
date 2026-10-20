using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Services.Est;
using Qertum.Services.Lifecycle;

namespace Qertum.Tests.Lifecycle;

public sealed class EstCredentialActivityTests
{
    [Fact]
    public async Task Activity_IsNewestFirst_AndAnEnrollmentShowsItsRequestsCurrentStatus()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();
        var credential = new EstEnrollmentCredential { Username = "device", PasswordHash = "x", IsEnabled = true };
        var request = new CertificateRequest
        {
            CommonName = "device.example.com", RequestedBy = "est", Type = "WebServer",
            Status = CertificateRequestStatus.Rejected, CreatedAtUtc = DateTime.UtcNow, UpdatedAtUtc = DateTime.UtcNow
        };
        db.EstEnrollmentCredentials.Add(credential);
        db.CertificateRequests.Add(request);
        db.LifecycleEvents.AddRange(
            Event(credential.Id, DiagnosticActions.AuthRefused, DiagnosticCategories.WrongPassword, null, DateTime.UtcNow.AddMinutes(-10)),
            Event(credential.Id, DiagnosticActions.Enrolled, null,
                $$"""{"certificateRequestId":"{{(Guid)request.Id}}","autoApproved":false}""", DateTime.UtcNow));
        await db.SaveChangesAsync(ct);

        var page = (await new EstCredentialActivityService(db).GetAsync(credential.Id, 1, 50, ct))!;

        Assert.Equal([DiagnosticActions.Enrolled, DiagnosticActions.AuthRefused], page.Items.Select(e => e.Action));
        Assert.Equal((Guid)request.Id, page.Items[0].RelatedRequestId);
        Assert.Equal("Rejected", page.Items[0].Category);
        Assert.Equal(DiagnosticHints.For(DiagnosticCategories.WrongPassword), page.Items[1].Hint);
    }

    [Fact]
    public async Task AnUnknownCredential_IsNull()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();

        Assert.Null(await new EstCredentialActivityService(db).GetAsync(Guid.NewGuid(), 1, 50, ct));
    }

    [Fact]
    public async Task TheTypedClient_ReadsARealActivityResponse_AndAnUnknownCredentialIsNull()
    {
        // The Web page and `qca est credentials activity` both read through this client.
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        Guid credentialId;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            var credential = new EstEnrollmentCredential { Username = "cli-device", PasswordHash = "x", IsEnabled = true };
            db.EstEnrollmentCredentials.Add(credential);
            db.LifecycleEvents.Add(Event(credential.Id, DiagnosticActions.AuthRefused, DiagnosticCategories.Disabled, null, DateTime.UtcNow));
            await db.SaveChangesAsync(ct);
            credentialId = credential.Id;
        }
        var http = factory.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        var client = new CertificateRequestsApiClient(http);

        var page = await client.GetEstCredentialActivityAsync(credentialId, 1, 50, ct);

        var entry = Assert.Single(page!.Items);
        Assert.Equal(DiagnosticActions.AuthRefused, entry.Action);
        Assert.Equal(DiagnosticCategories.Disabled, entry.Category);
        Assert.False(string.IsNullOrWhiteSpace(entry.Hint));
        Assert.Null(await client.GetEstCredentialActivityAsync(Guid.NewGuid(), 1, 50, ct));
    }

    private static LifecycleEvent Event(Guid credentialId, string action, string? category, string? data, DateTime at) => new()
    {
        Id = Guid.NewGuid(), Kind = LifecycleEventKinds.Diagnostic, OccurredAtUtc = at,
        SubjectType = LifecycleSubjectTypes.EstCredential, SubjectId = credentialId,
        Action = action, Category = category, DataJson = data, PerformedBy = $"est:{credentialId}"
    };
}
