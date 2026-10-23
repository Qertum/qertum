using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Lifecycle;
using Qertum.Services.Policies;
using Qertum.Tests.Issuers;

namespace Qertum.Tests.Policies;

public sealed class IssuerStrengthApiTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ANewCa_WarnsByDefault()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        Assert.Equal(IssuerStrengthMode.Warn, (await scope.Db.Settings.AsNoTracking().SingleAsync(Ct)).IssuerStrengthMode);
    }

    [Fact]
    public async Task Setting_IsStored_AndAuditedWithBothModes()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);

        var updated = await scope.CreateRequestService().SetIssuerStrengthAsync(IssuerStrengthMode.Enforce, "root-admin", Ct);

        Assert.Equal(IssuerStrengthMode.Enforce, updated.IssuerStrengthMode);
        Assert.Equal(IssuerStrengthMode.Enforce, (await scope.Db.Settings.AsNoTracking().SingleAsync(Ct)).IssuerStrengthMode);
        var entry = Assert.Single(scope.Audit.Entries, e => e.Action == "IssuerStrengthChanged");
        Assert.Contains("Warn", entry.Detail);
        Assert.Contains("Enforce", entry.Detail);
    }

    [Fact]
    public async Task Off_IsARealValue_NotSwallowedByTheColumnDefault()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);

        await scope.CreateRequestService().SetIssuerStrengthAsync(IssuerStrengthMode.Off, "root-admin", Ct);

        Assert.Equal(IssuerStrengthMode.Off, (await scope.Db.Settings.AsNoTracking().SingleAsync(Ct)).IssuerStrengthMode);
    }

    [Fact]
    public async Task SettingTheSameValue_WritesNothing()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        await scope.CreateRequestService().SetIssuerStrengthAsync(IssuerStrengthMode.Warn, "root-admin", Ct);
        Assert.DoesNotContain(scope.Audit.Entries, e => e.Action == "IssuerStrengthChanged");
    }

    [Fact]
    public async Task AGeneralSettingsSave_CannotChangeTheStoredValue()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        var service = scope.CreateRequestService();
        await service.GetSettingsAsync(Ct);

        await service.SetupOrUpdateSettingsAsync(
            new CaSettings { Id = 1, OrganizationName = "Acme", IssuerStrengthMode = IssuerStrengthMode.Off }, "settings-editor", Ct);

        Assert.Equal(IssuerStrengthMode.Warn, (await scope.Db.Settings.AsNoTracking().SingleAsync(Ct)).IssuerStrengthMode);
    }

    [Fact]
    public async Task ANewSettingsRow_IgnoresAForgedValue()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct, seedSettings: false);

        await scope.CreateRequestService().SetupOrUpdateSettingsAsync(
            new CaSettings { Id = 1, OrganizationName = "Acme", IssuerStrengthMode = IssuerStrengthMode.Off }, "settings-editor", Ct);

        Assert.Equal(IssuerStrengthMode.Warn, (await scope.Db.Settings.AsNoTracking().SingleAsync(Ct)).IssuerStrengthMode);
    }

    [Fact]
    public async Task Endpoint_IsAdminOnly_ValidatesTheMode_AndReturnsTheSettings()
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
        Assert.Equal(HttpStatusCode.Forbidden, (await editor.PutAsJsonAsync("/v1/settings/issuer-strength",
            new SetIssuerStrengthRequest { Mode = IssuerStrengthMode.Off }, Ct)).StatusCode);

        using var admin = factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        Assert.Equal(HttpStatusCode.BadRequest,
            (await admin.PutAsJsonAsync("/v1/settings/issuer-strength", new SetIssuerStrengthRequest(), Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PutAsJsonAsync("/v1/settings/issuer-strength",
            new { mode = 99 }, Ct)).StatusCode);

        var ok = await admin.PutAsJsonAsync("/v1/settings/issuer-strength",
            new SetIssuerStrengthRequest { Mode = IssuerStrengthMode.Enforce }, Ct);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Equal(IssuerStrengthMode.Enforce, (await ok.Content.ReadFromJsonAsync<CaSettings>(Ct))!.IssuerStrengthMode);
    }

    [Fact]
    public void TheEventIsInTheSettingsFamily_AndItsFieldsAreAllowlisted()
    {
        Assert.Equal(WebhookEventFamily.Settings, WellKnownWebhookEvents.FamilyOf(WellKnownWebhookEvents.IssuerStrengthChanged));
        Assert.Contains("mode", WebhookEventFields.For(WebhookEventFamily.Settings));
        Assert.Contains("previousMode", WebhookEventFields.For(WebhookEventFamily.Settings));
        Assert.True(AuditActionSubjects.IsKnown("IssuerStrengthChanged"));
    }
}

/// <summary>
/// The strength rule on every path that acts on a request: what preview says must be what create, approve and the
/// consumer's check do, and creating an intermediate obeys the same mode.
/// </summary>
public sealed class IssuerStrengthEndToEndTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static CreateIntermediateRequest Intermediate(CertificateKeyAlgorithm algorithm, IssuerId parent, string name, int pathLength = 0) => new()
    {
        Name = name, CommonName = name, KeyAlgorithm = algorithm, ValidityDays = 1825, ParentIssuerId = parent,
        PathLength = pathLength
    };

    /// <summary>A host whose default issuer signs with ML-DSA-65, under the classical test root.</summary>
    private static async Task<(IssuerApiHost Host, IssuerResponse Level3)> HostWithLevel3IssuerAsync()
    {
        var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        var root = await host.DefaultIssuerIdAsync(Ct);
        var created = await host.Admin().PostAsJsonAsync("/v1/issuers/intermediates",
            Intermediate(CertificateKeyAlgorithm.MlDsa65, root, "Level 3 CA", pathLength: 1), Ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode); // a classical parent is exempt
        var issuer = (await created.Content.ReadFromJsonAsync<CreateIntermediateResponse>(Ct))!.Issuer;
        Assert.Equal(HttpStatusCode.OK, (await host.Admin().PostAsync($"/v1/issuers/{issuer.Id}/make-default", null, Ct)).StatusCode);
        return (host, issuer);
    }

    private static Task<HttpResponseMessage> SetModeAsync(IssuerApiHost host, IssuerStrengthMode mode) =>
        host.Admin().PutAsJsonAsync("/v1/settings/issuer-strength", new SetIssuerStrengthRequest { Mode = mode }, Ct);

    private static CreateCertificateRequestRequest Leaf(CertificateKeyAlgorithm algorithm) => new()
    {
        CommonName = "www.corp.example",
        Type = "WebServer",
        PropertiesJson = "{\"dnsNames\":[\"www.corp.example\"]}",
        KeyAlgorithm = algorithm
    };

    [Theory]
    [InlineData(IssuerStrengthMode.Off, true, 0)]
    [InlineData(IssuerStrengthMode.Warn, true, 1)]
    [InlineData(IssuerStrengthMode.Enforce, false, 0)]
    public async Task PreviewAndCreateAgree_ForALevel5KeyUnderALevel3Issuer(IssuerStrengthMode mode, bool allowed, int warnings)
    {
        var (host, _) = await HostWithLevel3IssuerAsync();
        await using var _host = host;
        await SetModeAsync(host, mode);
        var client = host.Admin();

        var preview = (await (await client.PostAsJsonAsync("/v1/certificate-requests/preview", Leaf(CertificateKeyAlgorithm.MlDsa87), Ct))
            .Content.ReadFromJsonAsync<CertificateRequestPreviewResponse>(Ct))!;
        var create = await client.PostAsJsonAsync("/v1/certificate-requests", Leaf(CertificateKeyAlgorithm.MlDsa87), Ct);

        Assert.Equal(allowed, preview.Allowed);
        Assert.Equal(warnings, preview.Warnings.Count);
        if (allowed)
        {
            Assert.Equal(HttpStatusCode.Created, create.StatusCode);
            var row = (await create.Content.ReadFromJsonAsync<CertificateRequest>(Ct))!;
            Assert.Equal(warnings, row.Warnings?.Count ?? 0);
        }
        else
        {
            Assert.Equal(HttpStatusCode.BadRequest, create.StatusCode);
            Assert.Contains(preview.Violations, v => v.Rule == PolicyRules.IssuerStrength);
        }
    }

    [Fact]
    public async Task ALevel3KeyUnderALevel3Issuer_IsNotJudged()
    {
        var (host, _) = await HostWithLevel3IssuerAsync();
        await using var _host = host;
        await SetModeAsync(host, IssuerStrengthMode.Enforce);

        var preview = (await (await host.Admin().PostAsJsonAsync("/v1/certificate-requests/preview", Leaf(CertificateKeyAlgorithm.MlDsa65), Ct))
            .Content.ReadFromJsonAsync<CertificateRequestPreviewResponse>(Ct))!;

        Assert.True(preview.Allowed);
        Assert.Empty(preview.Warnings);
    }

    [Fact]
    public async Task Approve_AndTheConsumerCheck_RefuseWhenTheModeTightensAfterCreate()
    {
        var (host, _) = await HostWithLevel3IssuerAsync();
        await using var _host = host;
        var client = host.Admin();
        var created = (await (await client.PostAsJsonAsync("/v1/certificate-requests", Leaf(CertificateKeyAlgorithm.MlDsa87), Ct))
            .Content.ReadFromJsonAsync<CertificateRequest>(Ct))!; // Warn: allowed

        await SetModeAsync(host, IssuerStrengthMode.Enforce);

        var approvalPreview = (await client.GetFromJsonAsync<ApprovalPreviewResponse>($"/v1/certificate-requests/{created.Id}/approval-preview", Ct))!;
        Assert.False(approvalPreview.Allowed);
        Assert.Contains(approvalPreview.Violations, v => v.Rule == PolicyRules.IssuerStrength);
        var approve = await client.PostAsync($"/v1/certificate-requests/{created.Id}/approve", null, Ct);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, approve.StatusCode);

        using var scope = host.Factory.Services.CreateScope();
        var decision = await scope.ServiceProvider.GetRequiredService<ICertificateRequestService>()
            .CheckIssuancePolicyAsync(created.Id, Ct);
        Assert.False(decision.Allowed);
        Assert.Contains(decision.Violations, v => v.Rule == PolicyRules.IssuerStrength);
    }

    [Fact]
    public async Task CreatingAnIntermediate_FollowsTheMode()
    {
        var (host, level3) = await HostWithLevel3IssuerAsync();
        await using var _host = host;

        // Warn (default): created, and the audit entry carries the warning.
        var warned = await host.Admin().PostAsJsonAsync("/v1/issuers/intermediates",
            Intermediate(CertificateKeyAlgorithm.MlDsa87, level3.Id, "Level 5 CA"), Ct);
        Assert.Equal(HttpStatusCode.Created, warned.StatusCode);

        await SetModeAsync(host, IssuerStrengthMode.Enforce);
        var refused = await host.Admin().PostAsJsonAsync("/v1/issuers/intermediates",
            Intermediate(CertificateKeyAlgorithm.MlDsa87, level3.Id, "Level 5 CA 2"), Ct);
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Contains("level 5", await refused.Content.ReadAsStringAsync(Ct));

        var equal = await host.Admin().PostAsJsonAsync("/v1/issuers/intermediates",
            Intermediate(CertificateKeyAlgorithm.MlDsa65, level3.Id, "Level 3 CA 2"), Ct);
        Assert.Equal(HttpStatusCode.Created, equal.StatusCode);
    }
}
