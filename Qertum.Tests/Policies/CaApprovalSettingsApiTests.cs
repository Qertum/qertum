using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Lifecycle;

namespace Qertum.Tests.Policies;

public sealed class CaApprovalSettingsApiTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData(true, "independent")]
    [InlineData(false, "waived")]
    public void ModeNames_RoundTrip(bool require, string name)
    {
        Assert.Equal(name, CaApprovalRule.ModeName(require));
        Assert.True(CaApprovalRule.TryParse(name.ToUpperInvariant(), out var parsed));
        Assert.Equal(require, parsed);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("maybe")]
    public void TryParse_RefusesAnythingElse(string? text) => Assert.False(CaApprovalRule.TryParse(text, out _));

    [Fact]
    public async Task ANewCa_RequiresIndependentApprovalByDefault()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        var stored = await scope.Db.Settings.AsNoTracking().SingleAsync(Ct);
        Assert.True(stored.RequireIndependentCaApproval);
    }

    [Fact]
    public async Task SettingFalse_IsStoredAsFalse_AndAuditedWithBothModes()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        var service = scope.CreateRequestService();

        var updated = await service.SetCaApprovalRuleAsync(false, "root-admin", Ct);

        Assert.False(updated.RequireIndependentCaApproval);
        Assert.False((await scope.Db.Settings.AsNoTracking().SingleAsync(Ct)).RequireIndependentCaApproval);
        var entry = Assert.Single(scope.Audit.Entries, e => e.Action == "CaApprovalRuleChanged");
        Assert.Contains("independent", entry.Detail);
        Assert.Contains("waived", entry.Detail);
    }

    [Fact]
    public async Task SettingTheSameValue_WritesNothing()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        await scope.CreateRequestService().SetCaApprovalRuleAsync(true, "root-admin", Ct);
        Assert.DoesNotContain(scope.Audit.Entries, e => e.Action == "CaApprovalRuleChanged");
    }

    [Fact]
    public async Task AGeneralSettingsSave_CannotChangeTheStoredValue()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        var service = scope.CreateRequestService();
        await service.GetSettingsAsync(Ct);
        // A client posting the whole settings object with the rule switched off.
        var forged = new CaSettings { Id = 1, OrganizationName = "Acme", RequireIndependentCaApproval = false };

        await service.SetupOrUpdateSettingsAsync(forged, "settings-editor", Ct);

        Assert.True((await scope.Db.Settings.AsNoTracking().SingleAsync(Ct)).RequireIndependentCaApproval);
    }

    [Fact]
    public async Task ANewSettingsRow_IgnoresAForgedValue_AndStartsIndependent()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct, seedSettings: false);
        var forged = new CaSettings { Id = 1, OrganizationName = "Acme", RequireIndependentCaApproval = false };

        await scope.CreateRequestService().SetupOrUpdateSettingsAsync(forged, "settings-editor", Ct);

        Assert.True((await scope.Db.Settings.AsNoTracking().SingleAsync(Ct)).RequireIndependentCaApproval);
    }

    [Fact]
    public async Task Endpoint_IsAdminOnly_AndReturnsTheSettings()
    {
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, Ct);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            db.RolePermissions.Add(new RolePermission { Role = "editor", Permission = AppPermissions.SettingsEdit });
            await db.SaveChangesAsync(Ct);
        }

        using var editor = factory.CreateClient();
        editor.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", "editor");
        var refused = await editor.PutAsJsonAsync("/v1/settings/ca-approval",
            new SetCaApprovalRequest { RequireIndependentApproval = false }, Ct);
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);

        using var admin = factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test"); // the plain "Test" identity is admin
        var bad = await admin.PutAsJsonAsync("/v1/settings/ca-approval", new SetCaApprovalRequest(), Ct);
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);

        var ok = await admin.PutAsJsonAsync("/v1/settings/ca-approval",
            new SetCaApprovalRequest { RequireIndependentApproval = false }, Ct);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.False((await ok.Content.ReadFromJsonAsync<CaSettings>(Ct))!.RequireIndependentCaApproval);
    }

    [Fact]
    public void TheEventIsInTheSettingsFamily_AndItsFieldsAreAllowlisted()
    {
        Assert.Equal(WebhookEventFamily.Settings, WellKnownWebhookEvents.FamilyOf(WellKnownWebhookEvents.CaApprovalRuleChanged));
        Assert.Contains("approvalMode", WebhookEventFields.For(WebhookEventFamily.Settings));
        Assert.Contains("previousApprovalMode", WebhookEventFields.For(WebhookEventFamily.Settings));
        Assert.True(AuditActionSubjects.IsKnown("CaApprovalRuleChanged"));
    }
}
