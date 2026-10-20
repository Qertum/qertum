using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;

namespace Qertum.Tests;

public sealed class CertificateNoteApiTests
{
    private sealed class Arranged(WebApplicationFactory<ApiServiceProgram> factory, Guid requestId, Guid otherRequestId) : IAsyncDisposable
    {
        public WebApplicationFactory<ApiServiceProgram> Factory { get; } = factory;
        public Guid RequestId { get; } = requestId;
        public Guid OtherRequestId { get; } = otherRequestId;

        /// <summary>Admin (no subject) when <paramref name="role"/> is null; otherwise a non-admin with subject "sub-{role}".</summary>
        public HttpClient As(string? role)
        {
            var client = Factory.CreateClient();
            client.DefaultRequestHeaders.Authorization = role is null
                ? new AuthenticationHeaderValue("Test")
                : new AuthenticationHeaderValue("Test-Role", role);
            return client;
        }

        public string Url(Guid? requestId = null, Guid? noteId = null) =>
            $"/v1/certificate-requests/{requestId ?? RequestId}/notes" + (noteId is null ? "" : $"/{noteId}");

        public ValueTask DisposeAsync() => Factory.DisposeAsync();
    }

    // Roles: alice, bob = certificates.view; manager = view + manage; creator = create only.
    private static async Task<Arranged> ArrangeAsync()
    {
        var ct = TestContext.Current.CancellationToken;
        var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        db.RolePermissions.AddRange(
            new RolePermission { Role = "alice", Permission = AppPermissions.CertificatesView },
            new RolePermission { Role = "bob", Permission = AppPermissions.CertificatesView },
            new RolePermission { Role = "manager", Permission = AppPermissions.CertificatesView },
            new RolePermission { Role = "manager", Permission = AppPermissions.CertificatesManage },
            new RolePermission { Role = "creator", Permission = AppPermissions.CertificatesCreate });
        var request = new CertificateRequest { CommonName = "notes.contoso.local", RequestedBy = "Alice", Type = "WebServer", Status = CertificateRequestStatus.Pending };
        var other = new CertificateRequest { CommonName = "other.contoso.local", RequestedBy = "Alice", Type = "WebServer", Status = CertificateRequestStatus.Pending };
        db.CertificateRequests.AddRange(request, other);
        await db.SaveChangesAsync(ct);
        return new Arranged(factory, request.Id.Value, other.Id.Value);
    }

    private static async Task<CertificateNote> AddAsync(Arranged arranged, string role, string body, Guid? requestId = null)
    {
        using var client = arranged.As(role);
        var response = await client.PostAsJsonAsync(arranged.Url(requestId), new { body }, TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<CertificateNote>(TestContext.Current.CancellationToken))!;
    }

    [Fact]
    public async Task Post_AsAViewer_Creates201_WithTheAuthorFromTheToken()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var alice = arranged.As("alice");

        var response = await alice.PostAsJsonAsync(arranged.Url(), new { body = "hello" }, ct);
        var note = await response.Content.ReadFromJsonAsync<CertificateNote>(ct);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("hello", note!.Body);
        Assert.Equal("sub-alice", note.AuthorSubject);
        Assert.Equal(arranged.RequestId, note.RequestId.Value);
    }

    [Fact]
    public async Task Post_WithoutCertificatesView_Is403_AndAnonymousIs401()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var creator = arranged.As("creator");
        using var anonymous = arranged.Factory.CreateClient();

        Assert.Equal(HttpStatusCode.Forbidden, (await creator.PostAsJsonAsync(arranged.Url(), new { body = "x" }, ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsJsonAsync(arranged.Url(), new { body = "x" }, ct)).StatusCode);
    }

    [Fact]
    public async Task Post_ByACallerWithNoSubject_Is403()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var admin = arranged.As(null);   // the test admin carries no sub

        var response = await admin.PostAsJsonAsync(arranged.Url(), new { body = "x" }, ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Post_UnknownRequest_Is404_BeforeValidation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var alice = arranged.As("alice");

        var response = await alice.PostAsJsonAsync(arranged.Url(Guid.NewGuid()), new { body = "" }, ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData("\u001b[2J")]
    [InlineData("-----BEGIN PRIVATE KEY-----")]
    public async Task Post_InvalidBody_Is400(string body)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var alice = arranged.As("alice");

        var response = await alice.PostAsJsonAsync(arranged.Url(), new { body }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Put_ByTheAuthor_Updates200()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        var note = await AddAsync(arranged, "alice", "first");
        using var alice = arranged.As("alice");

        var response = await alice.PutAsJsonAsync(arranged.Url(noteId: note.Id.Value), new { body = "second" }, ct);
        var edited = await response.Content.ReadFromJsonAsync<CertificateNote>(ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("second", edited!.Body);
    }

    [Theory]
    [InlineData("bob")]
    [InlineData("manager")]
    public async Task Put_ByAnotherViewerOrAManager_Is403_AndChangesNothing(string role)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        var note = await AddAsync(arranged, "alice", "mine");
        using var other = arranged.As(role);

        var response = await other.PutAsJsonAsync(arranged.Url(noteId: note.Id.Value), new { body = "hijacked" }, ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        using var scope = arranged.Factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.Equal("mine", (await db.CertificateNotes.AsNoTracking().SingleAsync(ct)).Body);
    }

    [Fact]
    public async Task Put_ByAnAdministrator_Is403_BecauseOnlyTheAuthorEdits()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        var note = await AddAsync(arranged, "alice", "mine");
        using var admin = arranged.As(null);

        var response = await admin.PutAsJsonAsync(arranged.Url(noteId: note.Id.Value), new { body = "hijacked" }, ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Put_ByAStranger_WithAnInvalidBody_Is403_BeforeValidation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        var note = await AddAsync(arranged, "alice", "mine");
        using var bob = arranged.As("bob");

        var response = await bob.PutAsJsonAsync(arranged.Url(noteId: note.Id.Value), new { body = "" }, ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Put_AndDelete_ThroughTheWrongRequest_Are404()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        var note = await AddAsync(arranged, "alice", "mine");
        using var alice = arranged.As("alice");

        var put = await alice.PutAsJsonAsync(arranged.Url(arranged.OtherRequestId, note.Id.Value), new { body = "x" }, ct);
        var delete = await alice.DeleteAsync(arranged.Url(arranged.OtherRequestId, note.Id.Value), ct);

        Assert.Equal(HttpStatusCode.NotFound, put.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, delete.StatusCode);
    }

    [Fact]
    public async Task Delete_ByTheAuthor_Is204_AndTheNoteIsGone()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        var note = await AddAsync(arranged, "alice", "bye");
        using var alice = arranged.As("alice");

        var response = await alice.DeleteAsync(arranged.Url(noteId: note.Id.Value), ct);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        using var scope = arranged.Factory.Services.CreateScope();
        Assert.Empty(await scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>().CertificateNotes.ToListAsync(ct));
    }

    [Theory]
    [InlineData("bob")]
    [InlineData("manager")]
    public async Task Delete_ByAnyoneButTheAuthor_Is403_AndKeepsTheNote(string role)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        var note = await AddAsync(arranged, "alice", "mine");
        using var other = arranged.As(role);

        var response = await other.DeleteAsync(arranged.Url(noteId: note.Id.Value), ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        using var scope = arranged.Factory.Services.CreateScope();
        Assert.Single(await scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>().CertificateNotes.ToListAsync(ct));
    }

    [Fact]
    public async Task Delete_UnknownNote_Is404()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var alice = arranged.As("alice");

        var response = await alice.DeleteAsync(arranged.Url(noteId: Guid.NewGuid()), ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Post_TheTwoHundredAndFirstNote_Is409()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using (var scope = arranged.Factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            for (var i = 0; i < CertificateNote.MaxPerRequest; i++)
                db.CertificateNotes.Add(new CertificateNote
                {
                    RequestId = arranged.RequestId, Body = $"n{i}", AuthorSubject = "sub-alice", AuthorName = "Alice",
                    CreatedAtUtc = DateTime.UtcNow, UpdatedAtUtc = DateTime.UtcNow
                });
            await db.SaveChangesAsync(ct);
        }
        using var alice = arranged.As("alice");

        var response = await alice.PostAsJsonAsync(arranged.Url(), new { body = "one too many" }, ct);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task TheTimeline_ShowsTheNote_MarkedMineOnlyForItsAuthor()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        await AddAsync(arranged, "alice", "visible to all");
        using var alice = arranged.As("alice");
        using var bob = arranged.As("bob");

        var asAlice = await alice.GetFromJsonAsync<CertificateTimelineResponse>($"/v1/certificate-requests/{arranged.RequestId}/timeline", ct);
        var asBob = await bob.GetFromJsonAsync<CertificateTimelineResponse>($"/v1/certificate-requests/{arranged.RequestId}/timeline", ct);

        Assert.True(Assert.Single(asAlice!.Entries, e => e.Kind == TimelineEntryKind.Note).Mine);
        var seen = Assert.Single(asBob!.Entries, e => e.Kind == TimelineEntryKind.Note);
        Assert.False(seen.Mine);
        Assert.Equal("visible to all", seen.Detail);
    }
}
