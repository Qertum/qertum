using System.Net.Http.Json;

using Qertum.Services;

namespace Qertum.Tests.Aspire;

[Collection("AspireIntegration")]
public sealed class SettingsTests(AspireIntegrationFixture fixture)
{
    [Fact(DisplayName = "IT-SETTINGS-001")]
    public async Task Settings_Get_ReturnsDefaults()
    {
        // Act
        var resp = await fixture.ApiClientAsAdmin.GetAsync("/v1/settings", TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var settings = await resp.Content.ReadFromJsonAsync<CaSettings>(TestContext.Current.CancellationToken);
        Assert.NotNull(settings);
        Assert.True(settings.ExpiringSoonDays > 0);
    }

    [Fact(DisplayName = "IT-SETTINGS-002")]
    public async Task Settings_Put_UpdatesValues()
    {
        // Arrange
        var getResp = await fixture.ApiClientAsAdmin.GetAsync("/v1/settings", TestContext.Current.CancellationToken);
        var original = await getResp.Content.ReadFromJsonAsync<CaSettings>(TestContext.Current.CancellationToken);

        try
        {
            var update = new CaSettings
            {
                OrganizationName = "Contoso",
                Country = "US",
                ExpiringSoonDays = 60,
                CertificateValidityDays = 730,
                CrlValidityHours = 48
            };

            // Act
            var putResp = await fixture.ApiClientAsAdmin.PutAsJsonAsync("/v1/settings", update, TestContext.Current.CancellationToken);

            // Assert
            Assert.Equal(HttpStatusCode.OK, putResp.StatusCode);
            var updated = await putResp.Content.ReadFromJsonAsync<CaSettings>(TestContext.Current.CancellationToken);
            Assert.NotNull(updated);
            Assert.Equal("Contoso", updated.OrganizationName);
            Assert.Equal("US", updated.Country);
            Assert.Equal(60, updated.ExpiringSoonDays);
            Assert.Equal(730, updated.CertificateValidityDays);
            Assert.Equal(48, updated.CrlValidityHours);
        }
        finally
        {
            // Restore
            if (original != null)
                await fixture.ApiClientAsAdmin.PutAsJsonAsync("/v1/settings", original, TestContext.Current.CancellationToken);
        }
    }

    [Fact(DisplayName = "IT-SETTINGS-003")]
    public async Task Settings_Put_InvalidCountryCode_Rejected()
    {
        // Arrange
        var getResp = await fixture.ApiClientAsAdmin.GetAsync("/v1/settings", TestContext.Current.CancellationToken);
        var settings = await getResp.Content.ReadFromJsonAsync<CaSettings>(TestContext.Current.CancellationToken);
        settings!.Country = "XX";

        // Act
        var putResp = await fixture.ApiClientAsAdmin.PutAsJsonAsync("/v1/settings", settings, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, putResp.StatusCode);
        var body = await putResp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("ISO 3166-1 alpha-2", body, StringComparison.OrdinalIgnoreCase);
    }
    
    [Fact(DisplayName = "IT-SETTINGS-004")]
    public async Task Settings_Put_InvalidDnCharacter_Rejected()
    {
        // Arrange
        var getResp = await fixture.ApiClientAsAdmin.GetAsync("/v1/settings", TestContext.Current.CancellationToken);
        var settings = await getResp.Content.ReadFromJsonAsync<CaSettings>(TestContext.Current.CancellationToken);
        settings!.OrganizationName = "Acme, Inc."; // contains comma

        // Act
        var putResp = await fixture.ApiClientAsAdmin.PutAsJsonAsync("/v1/settings", settings, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, putResp.StatusCode);
    }

    [Fact(DisplayName = "IT-SETTINGS-005")]
    public async Task Settings_Put_AsViewer_Forbidden()
    {
        // Arrange
        var getResp = await fixture.ApiClientAsAdmin.GetAsync("/v1/settings", TestContext.Current.CancellationToken);
        var settings = await getResp.Content.ReadFromJsonAsync<CaSettings>(TestContext.Current.CancellationToken);

        // Act
        var putResp = await fixture.ApiClientAsViewer.PutAsJsonAsync("/v1/settings", settings, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, putResp.StatusCode);
    }
}
