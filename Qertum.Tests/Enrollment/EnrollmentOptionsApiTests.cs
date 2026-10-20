using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.Enrollment;

public sealed class EnrollmentOptionsApiTests
{
    private const string Route = "/v1/enrollment/options";
    private const string AcmeUrl = "https://acme.example.test/acme/directory";
    private const string EstUrl = "https://est.example.test/.well-known/est";

    private static WebApplicationFactory<ApiServiceProgram> WithSettings(
        WebApplicationFactory<ApiServiceProgram> root, params (string Key, string Value)[] settings) =>
        root.WithWebHostBuilder(builder =>
        {
            foreach (var (key, value) in settings)
                builder.UseSetting(key, value);
        });

    private static HttpClient Admin(WebApplicationFactory<ApiServiceProgram> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        return client;
    }

    private static HttpClient AsRole(WebApplicationFactory<ApiServiceProgram> factory, string role)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", role);
        return client;
    }

    private static async Task SeedRoleAsync(WebApplicationFactory<ApiServiceProgram> factory, string role,
        string[] permissions, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        db.RolePermissions.AddRange(permissions.Select(p => new RolePermission { Role = role, Permission = p }));
        await db.SaveChangesAsync(ct);
    }

    private static async Task SeedSettingsAsync(WebApplicationFactory<ApiServiceProgram> factory,
        Action<CaSettings> configure, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var settings = await db.Settings.SingleOrDefaultAsync(s => s.Id == 1, ct);
        if (settings is null)
        {
            settings = new CaSettings { PqcStage = PqcStage.Off, Id = 1 };
            db.Settings.Add(settings);
        }
        configure(settings);
        await db.SaveChangesAsync(ct);
    }

    [Fact]
    public async Task RequiresCertificatesCreate()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedRoleAsync(factory, "enroll-viewer", [AppPermissions.CertificatesView], ct);
        using var viewer = AsRole(factory, "enroll-viewer");

        var response = await viewer.GetAsync(Route, ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task CreateOnlyRole_WithoutView_GetsOptions()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedRoleAsync(factory, "enroll-creator", [AppPermissions.CertificatesCreate, AppPermissions.CertificatesCa], ct);
        using var creator = AsRole(factory, "enroll-creator");

        var response = await creator.GetAsync(Route, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = (await response.Content.ReadFromJsonAsync<EnrollmentOptionsResponse>(ct))!;
        Assert.Contains(body.Templates, t => t.TypeKey == "WebServer");
        Assert.Equal(["WebServer"], body.Purposes.Single(p => p.Purpose == EnrollmentPurpose.WebServer).TemplateTypeKeys);
        Assert.Equal(["SubordinateCA"], body.Purposes.Single(p => p.Purpose == EnrollmentPurpose.SubordinateCa).TemplateTypeKeys);
        Assert.DoesNotContain(body.Purposes, p => p.Purpose == EnrollmentPurpose.Other);
    }

    [Fact]
    public async Task Routes_AreNull_WhenUrlsUnset()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var body = (await admin.GetFromJsonAsync<EnrollmentOptionsResponse>(Route, ct))!;

        Assert.Null(body.Acme);
        Assert.Null(body.Est);
    }

    [Fact]
    public async Task Routes_AreNull_WhenUrlsInvalid()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var root = ApiServiceTests.CreateFactory();
        var factory = WithSettings(root,
            ("Enrollment:AcmeDirectoryUrl", "/acme/directory"),
            ("Enrollment:EstBaseUrl", "ftp://est.example.test/.well-known/est"));
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var body = (await admin.GetFromJsonAsync<EnrollmentOptionsResponse>(Route, ct))!;

        Assert.Null(body.Acme);
        Assert.Null(body.Est);
    }

    [Fact]
    public async Task Routes_ReflectUrlsAndSettings()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var root = ApiServiceTests.CreateFactory();
        var factory = WithSettings(root, ("Enrollment:AcmeDirectoryUrl", AcmeUrl), ("Enrollment:EstBaseUrl", EstUrl));
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedSettingsAsync(factory, s =>
        {
            s.PqcStage = PqcStage.Enforce;
            s.AcmeTemplateTypeKey = "ClientAuth";
            s.EstTemplateTypeKey = "";
            s.AcmeRequireExternalAccountBinding = true;
            s.AcmeAutoApprove = true;
            s.EstAutoApprove = true;
        }, ct);
        using var admin = Admin(factory);

        var body = (await admin.GetFromJsonAsync<EnrollmentOptionsResponse>(Route, ct))!;

        Assert.Equal(PqcStage.Enforce, body.PqcStage);
        Assert.NotNull(body.Acme);
        Assert.Equal(AcmeUrl, body.Acme.DirectoryUrl);
        Assert.Equal("ClientAuth", body.Acme.TemplateTypeKey);
        Assert.True(body.Acme.ExternalAccountBindingRequired);
        Assert.True(body.Acme.AutoApprove);
        Assert.NotNull(body.Est);
        Assert.Equal(EstUrl, body.Est.BaseUrl);
        Assert.Equal("WebServer", body.Est.TemplateTypeKey);
        Assert.True(body.Est.AutoApprove);
    }

    [Fact]
    public async Task DefaultValidityDays_MatchesValidityDefaults()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedSettingsAsync(factory, s => s.CertificateValidityDays = 90, ct);
        using var admin = Admin(factory);

        var body = (await admin.GetFromJsonAsync<EnrollmentOptionsResponse>(Route, ct))!;

        Assert.Equal(90, body.Templates.Single(t => t.TypeKey == "WebServer").DefaultValidityDays);
        Assert.Equal(3650, body.Templates.Single(t => t.TypeKey == "SubordinateCA").DefaultValidityDays);
    }

    [Fact]
    public async Task WritesNothing_NoSettingsRowIsCreated()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct, seedSettings: false);
        using var admin = Admin(factory);

        var response = await admin.GetAsync(Route, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.False(await db.Settings.AnyAsync(ct));
    }

    [Fact]
    public async Task Response_ExposesExactlyTheAllowlistedProperties()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var root = ApiServiceTests.CreateFactory();
        var factory = WithSettings(root, ("Enrollment:AcmeDirectoryUrl", AcmeUrl), ("Enrollment:EstBaseUrl", EstUrl));
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        using var json = JsonDocument.Parse(await admin.GetStringAsync(Route, ct));
        var rootElement = json.RootElement;

        static string[] Names(JsonElement element) =>
            element.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal).ToArray();

        Assert.Equal(["acme", "est", "pqcStage", "purposes", "templates"], Names(rootElement));
        Assert.Equal(["purpose", "templateTypeKeys"], Names(rootElement.GetProperty("purposes")[0]));
        Assert.Equal(["defaultValidityDays", "description", "name", "pqcStage", "purposes", "sanTypes", "typeKey"],
            Names(rootElement.GetProperty("templates")[0]));
        Assert.Equal(["autoApprove", "directoryUrl", "externalAccountBindingRequired", "templateTypeKey"],
            Names(rootElement.GetProperty("acme")));
        Assert.Equal(["autoApprove", "baseUrl", "templateTypeKey"], Names(rootElement.GetProperty("est")));
    }

    [Fact]
    public async Task RestrictedTemplate_IsHiddenFromNonMember_AndFromPurposes()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedRoleAsync(factory, "enroll-creator", [AppPermissions.CertificatesCreate], ct);
        using (var scope = factory.Services.CreateScope())
            await Qertum.Tests.Policies.PolicySeeding.LinkPublishedPolicyAsync(
                scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>(), "WebServer", requesterRoles: ["ops"], ct: ct);

        var body = (await AsRole(factory, "enroll-creator").GetFromJsonAsync<EnrollmentOptionsResponse>(Route, ct))!;

        Assert.DoesNotContain(body.Templates, t => t.TypeKey == "WebServer");
        Assert.DoesNotContain(body.Purposes, p => p.TemplateTypeKeys.Contains("WebServer"));
        Assert.Contains(body.Templates, t => t.TypeKey == "ClientAuth"); // unlinked stays
    }

    [Fact]
    public async Task RestrictedTemplate_IsShownToMemberAndAdmin()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedRoleAsync(factory, "ops", [AppPermissions.CertificatesCreate], ct);
        using (var scope = factory.Services.CreateScope())
            await Qertum.Tests.Policies.PolicySeeding.LinkPublishedPolicyAsync(
                scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>(), "WebServer", requesterRoles: ["ops"], ct: ct);

        Assert.Contains((await AsRole(factory, "ops").GetFromJsonAsync<EnrollmentOptionsResponse>(Route, ct))!.Templates,
            t => t.TypeKey == "WebServer");
        Assert.Contains((await Admin(factory).GetFromJsonAsync<EnrollmentOptionsResponse>(Route, ct))!.Templates,
            t => t.TypeKey == "WebServer");
    }
}
