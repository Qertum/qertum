using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

public sealed class TemplateIssuerTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<CertificateTemplate> WebServerTemplateAsync(IssuerApiHost host) =>
        (await host.Admin().GetFromJsonAsync<List<CertificateTemplate>>("/v1/certificate-templates", Ct))!.Single(t => t.TypeKey == "WebServer");

    [Fact]
    public async Task Pin_ThenIssuance_UsesThePinnedIssuer()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        await host.DefaultIssuerIdAsync(Ct);
        var pinned = await host.Kit.AddOnlineRootAsync("Pinned Root");
        await host.Registry.InvalidateAsync(Ct);
        var template = await WebServerTemplateAsync(host);

        var response = await host.Admin().PutAsJsonAsync($"/v1/certificate-templates/{template.Id}/issuer",
            new SetTemplateIssuerRequest { IssuerId = pinned.Id }, Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var scope = host.Factory.Services.CreateScope();
        var signer = scope.ServiceProvider.GetRequiredService<IssuanceSigner>();
        var signed = await signer.SignAsync(new CertificateRequest { CommonName = "p.example", Type = "WebServer" }, new CaSettings { PqcStage = PqcStage.Off }, Ct);
        Assert.Equal(pinned.Id, signed.IssuerId);
    }

    [Fact]
    public async Task Pin_ToARetiredIssuer_Is422()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        var retired = await host.Kit.AddOnlineRootAsync("Retired", status: IssuerStatus.Retired);
        await host.Registry.InvalidateAsync(Ct);
        var template = await WebServerTemplateAsync(host);

        var response = await host.Admin().PutAsJsonAsync($"/v1/certificate-templates/{template.Id}/issuer",
            new SetTemplateIssuerRequest { IssuerId = retired.Id }, Ct);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
    }

    [Fact]
    public async Task Pin_ToAnUnknownIssuer_Is404()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        var template = await WebServerTemplateAsync(host);

        var response = await host.Admin().PutAsJsonAsync($"/v1/certificate-templates/{template.Id}/issuer",
            new SetTemplateIssuerRequest { IssuerId = new IssuerId(Guid.NewGuid()) }, Ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task CreateUnderATemplatePinnedToAnIssuerRetiredLater_Is409()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        await host.DefaultIssuerIdAsync(Ct);
        var pinned = await host.Kit.AddOnlineRootAsync("Soon Retired");
        await host.Registry.InvalidateAsync(Ct);
        var template = await WebServerTemplateAsync(host);
        (await host.Admin().PutAsJsonAsync($"/v1/certificate-templates/{template.Id}/issuer",
            new SetTemplateIssuerRequest { IssuerId = pinned.Id }, Ct)).EnsureSuccessStatusCode();
        (await host.Admin().PostAsync($"/v1/issuers/{pinned.Id}/retire", null, Ct)).EnsureSuccessStatusCode();

        var create = await host.Admin().PostAsJsonAsync("/v1/certificate-requests",
            new CreateCertificateRequestRequest { CommonName = "r.example", Type = "WebServer" }, Ct);

        Assert.Equal(HttpStatusCode.Conflict, create.StatusCode);
        Assert.Contains("Soon Retired", await create.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task Unpin_ReturnsToTheDefault_AndTemplateSaveDoesNotTouchThePin()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        await host.DefaultIssuerIdAsync(Ct);
        var pinned = await host.Kit.AddOnlineRootAsync("Kept Pin");
        await host.Registry.InvalidateAsync(Ct);
        var template = await WebServerTemplateAsync(host);
        (await host.Admin().PutAsJsonAsync($"/v1/certificate-templates/{template.Id}/issuer",
            new SetTemplateIssuerRequest { IssuerId = pinned.Id }, Ct)).EnsureSuccessStatusCode();

        (await host.Admin().PutAsJsonAsync($"/v1/certificate-templates/{template.Id}", new SaveCertificateTemplateRequest
        {
            Name = template.Name, TypeKey = template.TypeKey, Description = "edited", KeyUsagesJson = template.KeyUsagesJson,
            ExtendedKeyUsagesJson = template.ExtendedKeyUsagesJson, SanTypesJson = template.SanTypesJson,
            CustomExtensionsJson = template.CustomExtensionsJson, ValidityDays = template.ValidityDays
        }, Ct)).EnsureSuccessStatusCode();
        Assert.Equal(pinned.Id, (await WebServerTemplateAsync(host)).IssuerId);

        (await host.Admin().PutAsJsonAsync($"/v1/certificate-templates/{template.Id}/issuer", new SetTemplateIssuerRequest { IssuerId = null }, Ct))
            .EnsureSuccessStatusCode();
        Assert.Null((await WebServerTemplateAsync(host)).IssuerId);
    }

    [Fact]
    public async Task RequiresSettingsEdit()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        await host.GrantAsync("viewer", AppPermissions.CertificatesView);
        var template = await WebServerTemplateAsync(host);

        var response = await host.Role("viewer").PutAsJsonAsync($"/v1/certificate-templates/{template.Id}/issuer",
            new SetTemplateIssuerRequest { IssuerId = null }, Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
}
