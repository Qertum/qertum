using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Qertum.Services;
using Qertum.Services.Approvals;

namespace Qertum.Tests.Approvals;

public sealed class ApprovalServiceTests
{
    private static readonly ApprovalCaller Alice = new("sub-alice", "alice", IsAdmin: true);
    private static readonly ApprovalCaller Bob = new("sub-bob", "bob", IsAdmin: true);
    private static readonly ApprovalCaller User = new("sub-user", "user", IsAdmin: false);
    private static readonly Guid Target = Guid.NewGuid();

    private readonly SharedInMemoryDatabase _database = SharedInMemoryDatabase.Create(createSchema: true);
    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(2026, 10, 18, 12, 0, 0, TimeSpan.Zero));

    private ApprovalService NewService() => new(_database.CreateContext(), Options.Create(new ApprovalOptions()), _clock);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<ApprovalException> Refused(Func<Task> action) => await Assert.ThrowsAsync<ApprovalException>(action);

    private async Task<ApprovalRequest> RequestedAsync(ApprovalCaller? by = null, string operation = ApprovalOperations.BulkRevoke, string? target = null)
        => await NewService().RequestAsync(by ?? Alice, operation, target ?? Target.ToString(), "because", Ct);

    private async Task<ApprovalRequest> ApprovedAsync()
    {
        var request = await RequestedAsync();
        return await NewService().DecideAsync(request.Id, Bob, approve: true, null, Ct);
    }

    // ── request ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Request_RefusesUnknownOperation() =>
        Assert.Equal(ApprovalError.Invalid, (await Refused(() => NewService().RequestAsync(Alice, "make-coffee", "x", null, Ct))).Error);

    [Fact]
    public async Task Request_RefusesMissingTargetForTargetedOperation() =>
        Assert.Equal(ApprovalError.Invalid, (await Refused(() => NewService().RequestAsync(Alice, ApprovalOperations.IssuerRetire, null, null, Ct))).Error);

    [Fact]
    public async Task Request_RefusesATargetForCreateIntermediate() =>
        Assert.Equal(ApprovalError.Invalid, (await Refused(() => NewService().RequestAsync(Alice, ApprovalOperations.IssuerCreateIntermediate, "x", null, Ct))).Error);

    [Fact]
    public async Task Request_RefusesCallerWithoutSubject() =>
        Assert.Equal(ApprovalError.NotAllowed, (await Refused(() =>
            NewService().RequestAsync(new ApprovalCaller(null, "machine", true), ApprovalOperations.BulkRevoke, "x", null, Ct))).Error);

    [Fact]
    public async Task Request_RefusesSecondOpenRequestForSameCallerOperationTarget()
    {
        await RequestedAsync();
        Assert.Equal(ApprovalError.Conflict, (await Refused(() => RequestedAsync())).Error);
    }

    [Fact]
    public async Task Request_AllowsANewRequestOnceTheOldOneExpired()
    {
        await RequestedAsync();
        _clock.Advance(TimeSpan.FromHours(25));
        await RequestedAsync();
    }

    [Fact]
    public async Task Request_ConcurrentDuplicates_FileExactlyOne()
    {
        var results = await Task.WhenAll(
            Try(() => RequestedAsync()),
            Try(() => RequestedAsync()),
            Try(() => RequestedAsync()));

        Assert.Single(results, ok => ok);
        await using var db = _database.CreateContext();
        Assert.Equal(1, await db.ApprovalRequests.CountAsync(Ct));
    }

    [Theory]
    [InlineData("bad\u001b[31mnote")]
    [InlineData("tab\tseparated")]
    public async Task Request_RejectsControlCharactersInTheNote(string note) =>
        Assert.Equal(ApprovalError.Invalid, (await Refused(() =>
            NewService().RequestAsync(Alice, ApprovalOperations.BulkRevoke, "x", note, Ct))).Error);

    [Fact]
    public async Task Request_RejectsANoteOver500Characters() =>
        Assert.Equal(ApprovalError.Invalid, (await Refused(() =>
            NewService().RequestAsync(Alice, ApprovalOperations.BulkRevoke, "x", new string('a', 501), Ct))).Error);

    [Fact]
    public async Task Request_TrimsTheNoteAndNormalizesLineBreaks()
    {
        var request = await NewService().RequestAsync(Alice, ApprovalOperations.BulkRevoke, "x", "  one\r\ntwo\rthree  ", Ct);
        Assert.Equal("one\ntwo\nthree", request.Note);
        Assert.Equal(ApprovalStatus.Pending, request.Status);
        Assert.Equal(_clock.GetUtcNow().UtcDateTime, request.RequestedAtUtc);
    }

    [Fact]
    public async Task Request_StoresAGuidTargetInOneForm_SoTheCaseOrBracesTheRequesterTypedDoNotMatter()
    {
        var typed = "{" + Target.ToString().ToUpperInvariant() + "}";
        var request = await NewService().RequestAsync(Alice, ApprovalOperations.BulkRevoke, typed, null, Ct);
        await NewService().DecideAsync(request.Id, Bob, true, null, Ct);

        Assert.Equal(Target.ToString(), request.TargetId);
        Assert.NotNull(await NewService().ClaimAsync("sub-alice", ApprovalOperations.BulkRevoke, Target.ToString().ToUpperInvariant(), Ct));
    }

    // ── decide ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Decide_RefusesNonAdmin()
    {
        var request = await RequestedAsync();
        Assert.Equal(ApprovalError.NotAllowed, (await Refused(() => NewService().DecideAsync(request.Id, User, true, null, Ct))).Error);
    }

    [Fact]
    public async Task Decide_RefusesTheRequester()
    {
        var request = await RequestedAsync();
        Assert.Equal(ApprovalError.NotAllowed, (await Refused(() => NewService().DecideAsync(request.Id, Alice, true, null, Ct))).Error);
    }

    [Fact]
    public async Task Decide_RefusesDeciderWithoutSubject()
    {
        var request = await RequestedAsync();
        Assert.Equal(ApprovalError.NotAllowed, (await Refused(() =>
            NewService().DecideAsync(request.Id, new ApprovalCaller(null, "machine", true), true, null, Ct))).Error);
    }

    [Fact]
    public async Task Decide_UnknownRequestIsNotFound() =>
        Assert.Equal(ApprovalError.NotFound, (await Refused(() => NewService().DecideAsync(new ApprovalRequestId(Guid.NewGuid()), Bob, true, null, Ct))).Error);

    [Fact]
    public async Task Approve_SetsGrantExpiryFromTheWindow()
    {
        var approved = await ApprovedAsync();
        Assert.Equal(ApprovalStatus.Approved, approved.Status);
        Assert.Equal("sub-bob", approved.DecidedBySubject);
        Assert.Equal(_clock.GetUtcNow().UtcDateTime.AddMinutes(15), approved.GrantExpiresAtUtc);
    }

    [Fact]
    public async Task Deny_RecordsTheNoteAndNoGrant()
    {
        var request = await RequestedAsync();
        var denied = await NewService().DecideAsync(request.Id, Bob, approve: false, "no", Ct);
        Assert.Equal(ApprovalStatus.Denied, denied.Status);
        Assert.Equal("no", denied.DecisionNote);
        Assert.Null(denied.GrantExpiresAtUtc);
    }

    [Fact]
    public async Task Decide_ExpiredPendingRequestIsAConflict()
    {
        var request = await RequestedAsync();
        _clock.Advance(TimeSpan.FromHours(25));
        Assert.Equal(ApprovalError.Conflict, (await Refused(() => NewService().DecideAsync(request.Id, Bob, true, null, Ct))).Error);
    }

    [Fact]
    public async Task Decide_TwiceConcurrentlyHasExactlyOneWinner()
    {
        var request = await RequestedAsync();
        var carol = new ApprovalCaller("sub-carol", "carol", true);
        var results = await Task.WhenAll(
            Try(() => NewService().DecideAsync(request.Id, Bob, true, null, Ct)),
            Try(() => NewService().DecideAsync(request.Id, carol, true, null, Ct)));
        Assert.Single(results, ok => ok);
        Assert.Single(results, ok => !ok);
    }

    private static async Task<bool> Try(Func<Task> action)
    {
        try { await action(); return true; }
        catch (ApprovalException ex) when (ex.Error == ApprovalError.Conflict) { return false; }
    }

    // ── effective status ───────────────────────────────────────────────────────

    [Fact]
    public async Task EffectiveStatus_PendingBecomesExpiredAfterRequestTtl()
    {
        var request = await RequestedAsync();
        Assert.Equal(ApprovalStatus.Pending, NewService().EffectiveStatus(request));
        _clock.Advance(TimeSpan.FromHours(24));
        Assert.Equal(ApprovalStatus.Expired, NewService().EffectiveStatus(request));
    }

    [Fact]
    public async Task EffectiveStatus_ApprovedBecomesExpiredAfterTheGrantWindow()
    {
        var approved = await ApprovedAsync();
        _clock.Advance(TimeSpan.FromMinutes(14));
        Assert.Equal(ApprovalStatus.Approved, NewService().EffectiveStatus(approved));
        _clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(ApprovalStatus.Expired, NewService().EffectiveStatus(approved));
    }

    // ── claim and release ──────────────────────────────────────────────────────

    [Fact]
    public async Task Claim_ReturnsTheIdOnceThenNull()
    {
        var approved = await ApprovedAsync();
        Assert.Equal(approved.Id, await NewService().ClaimAsync("sub-alice", ApprovalOperations.BulkRevoke, Target.ToString(), Ct));
        Assert.Null(await NewService().ClaimAsync("sub-alice", ApprovalOperations.BulkRevoke, Target.ToString(), Ct));
        Assert.Equal(ApprovalStatus.Used, (await NewService().GetAsync(approved.Id, Ct))!.Status);
    }

    [Fact]
    public async Task Claim_IgnoresOtherSubjectOtherTargetOtherOperationAndExpiredGrants()
    {
        await ApprovedAsync();
        var service = NewService();
        Assert.Null(await service.ClaimAsync("sub-bob", ApprovalOperations.BulkRevoke, Target.ToString(), Ct));
        Assert.Null(await service.ClaimAsync("sub-alice", ApprovalOperations.BulkRevoke, Guid.NewGuid().ToString(), Ct));
        Assert.Null(await service.ClaimAsync("sub-alice", ApprovalOperations.PolicyPublish, Target.ToString(), Ct));
        _clock.Advance(TimeSpan.FromMinutes(16));
        Assert.Null(await service.ClaimAsync("sub-alice", ApprovalOperations.BulkRevoke, Target.ToString(), Ct));
    }

    [Fact]
    public async Task Claim_ConcurrentCallsHaveOneWinner()
    {
        await ApprovedAsync();
        var claims = await Task.WhenAll(
            NewService().ClaimAsync("sub-alice", ApprovalOperations.BulkRevoke, Target.ToString(), Ct),
            NewService().ClaimAsync("sub-alice", ApprovalOperations.BulkRevoke, Target.ToString(), Ct));
        Assert.Single(claims, id => id is not null);
    }

    [Fact]
    public async Task Release_RestoresApprovedWhileTheWindowIsOpen()
    {
        var approved = await ApprovedAsync();
        var id = await NewService().ClaimAsync("sub-alice", ApprovalOperations.BulkRevoke, Target.ToString(), Ct);
        await NewService().ReleaseAsync(id!.Value, Ct);
        var restored = (await NewService().GetAsync(approved.Id, Ct))!;
        Assert.Equal(ApprovalStatus.Approved, restored.Status);
        Assert.Null(restored.UsedAtUtc);
        Assert.NotNull(await NewService().ClaimAsync("sub-alice", ApprovalOperations.BulkRevoke, Target.ToString(), Ct));
    }

    [Fact]
    public async Task Release_DoesNothingOnceTheWindowHasClosed()
    {
        var approved = await ApprovedAsync();
        var id = await NewService().ClaimAsync("sub-alice", ApprovalOperations.BulkRevoke, Target.ToString(), Ct);
        _clock.Advance(TimeSpan.FromMinutes(16));
        await NewService().ReleaseAsync(id!.Value, Ct);
        Assert.Equal(ApprovalStatus.Used, (await NewService().GetAsync(approved.Id, Ct))!.Status);
    }

    // ── flag and list ──────────────────────────────────────────────────────────

    [Fact]
    public async Task IsEnabled_FalseWithoutASettingsRowAndDoesNotInsertOne()
    {
        var empty = SharedInMemoryDatabase.Create(createSchema: true, seedSettings: false);
        var service = new ApprovalService(empty.CreateContext(), Options.Create(new ApprovalOptions()), _clock);
        Assert.False(await service.IsEnabledAsync(Ct));
        Assert.False(await empty.CreateContext().Settings.AnyAsync(Ct));
    }

    [Fact]
    public async Task IsEnabled_ReadsTheFlag()
    {
        Assert.False(await NewService().IsEnabledAsync(Ct));
        await using (var db = _database.CreateContext())
            await db.Settings.ExecuteUpdateAsync(s => s.SetProperty(x => x.RequireTwoPersonApproval, true), Ct);
        Assert.True(await NewService().IsEnabledAsync(Ct));
    }

    [Fact]
    public async Task List_NonAdminSeesOnlyOwnAndAdminSeesAll()
    {
        await RequestedAsync(Alice);
        await RequestedAsync(Bob, target: Guid.NewGuid().ToString());
        var user = await NewService().ListAsync(User, null, false, 1, 50, Ct);
        var bobMine = await NewService().ListAsync(Bob, null, mineOnly: true, 1, 50, Ct);
        var bobAll = await NewService().ListAsync(Bob, null, mineOnly: false, 1, 50, Ct);
        Assert.Equal(0, user.TotalCount);
        Assert.Equal(1, bobMine.TotalCount);
        Assert.Equal(2, bobAll.TotalCount);
    }

    [Fact]
    public async Task List_FiltersByEffectiveStatus()
    {
        await RequestedAsync(Alice);
        _clock.Advance(TimeSpan.FromHours(25));
        Assert.Equal(1, (await NewService().ListAsync(Bob, ApprovalStatus.Expired, false, 1, 50, Ct)).TotalCount);
        Assert.Equal(0, (await NewService().ListAsync(Bob, ApprovalStatus.Pending, false, 1, 50, Ct)).TotalCount);
    }
}
