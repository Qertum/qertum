using System.Net.Http.Json;
using System.Text.Json;
using Qertum.Services;

namespace Qertum.Tests.Aspire;

[Collection("AspireIntegration")]
public sealed class CertificateRequestCrudTests(AspireIntegrationFixture fixture)
{
    // ── Unauthenticated rejection ──────────────────────────────────────────────

    [Fact(DisplayName = "IT-CERT-UNAUTH-001")]
    public async Task GetCertificateRequests_Anonymous_Returns401()
    {
        var response = await fixture.ApiClientAnon.GetAsync("/v1/certificate-requests", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact(DisplayName = "IT-CERT-UNAUTH-002")]
    public async Task PostCertificateRequests_Anonymous_Returns401()
    {
        var response = await fixture.ApiClientAnon.PostAsJsonAsync("/v1/certificate-requests", new
        {
            CommonName = TestHelpers.UniqueCN(),
            RequestedBy = "anon",
            Type = "WebServer",
            PropertiesJson = "{}"
        }, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ── CREATE ─────────────────────────────────────────────────────────────────

    [Fact(DisplayName = "IT-CERT-CREATE-001")]
    public async Task CreateCertificateRequest_ValidBody_Returns201WithExpectedFields()
    {
        var cn = TestHelpers.UniqueCN();
        var response = await fixture.ApiClientAsAdmin.PostAsJsonAsync("/v1/certificate-requests", new
        {
            CommonName = cn,
            RequestedBy = "it-test-user",
            Type = "WebServer",
            PropertiesJson = "{}"
        }, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.NotNull(response.Headers.Location);
        Assert.Contains("/v1/certificate-requests/", response.Headers.Location!.ToString());

        var created = await response.Content.ReadFromJsonAsync<CertificateRequest>(TestContext.Current.CancellationToken);
        Assert.NotNull(created);
        Assert.NotEqual(default(CertificateRequestId), created.Id);
        Assert.Equal(cn, created.CommonName);
        Assert.Equal(CertificateRequestStatus.Pending, created.Status);
        Assert.True(created.CreatedAtUtc >= DateTime.UtcNow.AddMinutes(-1));
    }

    [Fact(DisplayName = "IT-CERT-CREATE-002")]
    public async Task CreateCertificateRequest_DuplicateCommonName_Returns409()
    {
        var cn = TestHelpers.UniqueCN();
        var body = new { CommonName = cn, RequestedBy = "tester", Type = "WebServer", PropertiesJson = "{}" };

        var first = await fixture.ApiClientAsAdmin.PostAsJsonAsync("/v1/certificate-requests", body, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);

        var second = await fixture.ApiClientAsAdmin.PostAsJsonAsync("/v1/certificate-requests", body, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        var problem = await second.Content.ReadFromJsonAsync<JsonDocument>(TestContext.Current.CancellationToken);
        Assert.Equal("Duplicate Request", problem!.RootElement.GetProperty("title").GetString());
    }

    [Fact(DisplayName = "IT-CERT-CREATE-004")]
    public async Task CreateCertificateRequest_InvalidCommonNameChars_Returns400()
    {
        var response = await fixture.ApiClientAsAdmin.PostAsJsonAsync("/v1/certificate-requests", new
        {
            CommonName = "bad=name",
            RequestedBy = "tester",
            Type = "WebServer",
            PropertiesJson = "{}"
        }, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact(DisplayName = "IT-CERT-CREATE-005")]
    public async Task CreateCertificateRequest_WebServerWithSan_Returns201()
    {
        var cn = TestHelpers.UniqueCN();
        var response = await fixture.ApiClientAsAdmin.PostAsJsonAsync("/v1/certificate-requests", new
        {
            CommonName = cn,
            RequestedBy = "tester",
            Type = "WebServer",
            PropertiesJson = """{"dnsNames":["api.example.com","*.api.example.com"]}"""
        }, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await response.Content.ReadFromJsonAsync<CertificateRequest>(TestContext.Current.CancellationToken);
        Assert.NotNull(created);
        Assert.Contains("api.example.com", created.PropertiesJson);
    }

    [Fact(DisplayName = "IT-CERT-CREATE-006")]
    public async Task CreateCertificateRequest_InvalidSanDnsName_Returns400()
    {
        var response = await fixture.ApiClientAsAdmin.PostAsJsonAsync("/v1/certificate-requests", new
        {
            CommonName = TestHelpers.UniqueCN(),
            RequestedBy = "tester",
            Type = "WebServer",
            PropertiesJson = """{"dnsNames":["not a valid dns!"]}"""
        }, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("Invalid SAN DNS name", content);
    }

    [Fact(DisplayName = "IT-CERT-CREATE-008")]
    public async Task CreateCertificateRequest_AsViewer_Returns403()
    {
        var response = await fixture.ApiClientAsViewer.PostAsJsonAsync("/v1/certificate-requests", new
        {
            CommonName = TestHelpers.UniqueCN(),
            RequestedBy = "viewer-user",
            Type = "WebServer",
            PropertiesJson = "{}"
        }, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    // ── READ ───────────────────────────────────────────────────────────────────

    [Fact(DisplayName = "IT-CERT-READ-001")]
    public async Task ListCertificateRequests_ReturnsPagedResultContainingCreatedItems()
    {
        var cn1 = TestHelpers.UniqueCN();
        var cn2 = TestHelpers.UniqueCN();
        await fixture.ApiClientAsAdmin.PostAsJsonAsync("/v1/certificate-requests",
            new { CommonName = cn1, RequestedBy = "r", Type = "WebServer", PropertiesJson = "{}" }, TestContext.Current.CancellationToken);
        await fixture.ApiClientAsAdmin.PostAsJsonAsync("/v1/certificate-requests",
            new { CommonName = cn2, RequestedBy = "r", Type = "WebServer", PropertiesJson = "{}" }, TestContext.Current.CancellationToken);

        var response = await fixture.ApiClientAsAdmin.GetAsync("/v1/certificate-requests", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var paged = await response.Content.ReadFromJsonAsync<PagedResult<CertificateRequest>>(TestContext.Current.CancellationToken);
        Assert.NotNull(paged);
        Assert.True(paged.TotalCount >= 2);
        Assert.Contains(paged.Items, r => r.CommonName == cn1);
        Assert.Contains(paged.Items, r => r.CommonName == cn2);
    }

    [Fact(DisplayName = "IT-CERT-READ-002")]
    public async Task ListCertificateRequests_PageSize1_ReturnsOneItemPerPage()
    {
        await fixture.ApiClientAsAdmin.PostAsJsonAsync("/v1/certificate-requests",
            new { CommonName = TestHelpers.UniqueCN(), RequestedBy = "r", Type = "WebServer", PropertiesJson = "{}" }, TestContext.Current.CancellationToken);
        await fixture.ApiClientAsAdmin.PostAsJsonAsync("/v1/certificate-requests",
            new { CommonName = TestHelpers.UniqueCN(), RequestedBy = "r", Type = "WebServer", PropertiesJson = "{}" }, TestContext.Current.CancellationToken);

        var page1 = await (await fixture.ApiClientAsAdmin.GetAsync("/v1/certificate-requests?page=1&pageSize=1", TestContext.Current.CancellationToken))
            .Content.ReadFromJsonAsync<PagedResult<CertificateRequest>>(TestContext.Current.CancellationToken);
        var page2 = await (await fixture.ApiClientAsAdmin.GetAsync("/v1/certificate-requests?page=2&pageSize=1", TestContext.Current.CancellationToken))
            .Content.ReadFromJsonAsync<PagedResult<CertificateRequest>>(TestContext.Current.CancellationToken);

        Assert.NotNull(page1);
        Assert.NotNull(page2);
        Assert.Single(page1.Items);
        Assert.Single(page2.Items);
        Assert.NotEqual(page1.Items[0].Id, page2.Items[0].Id);
    }

    [Fact(DisplayName = "IT-CERT-READ-003")]
    public async Task GetCertificateRequestById_ReturnsMatchingRequest()
    {
        var cn = TestHelpers.UniqueCN();
        var createResp = await fixture.ApiClientAsAdmin.PostAsJsonAsync("/v1/certificate-requests",
            new { CommonName = cn, RequestedBy = "reader", Type = "WebServer", PropertiesJson = "{}" }, TestContext.Current.CancellationToken);
        var created = await createResp.Content.ReadFromJsonAsync<CertificateRequest>(TestContext.Current.CancellationToken);
        Assert.NotNull(created);

        var getResp = await fixture.ApiClientAsAdmin.GetAsync($"/v1/certificate-requests/{created.Id}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, getResp.StatusCode);
        var fetched = await getResp.Content.ReadFromJsonAsync<CertificateRequest>(TestContext.Current.CancellationToken);
        Assert.NotNull(fetched);
        Assert.Equal(created.Id, fetched.Id);
        Assert.Equal(cn, fetched.CommonName);
        Assert.Equal(CertificateRequestStatus.Pending, fetched.Status);
    }

    [Fact(DisplayName = "IT-CERT-READ-004")]
    public async Task GetCertificateRequestById_NotFound_Returns404()
    {
        var response = await fixture.ApiClientAsAdmin.GetAsync($"/v1/certificate-requests/{Guid.NewGuid()}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact(DisplayName = "IT-CERT-READ-005")]
    public async Task ListCertificateRequests_AsViewer_Returns200()
    {
        var response = await fixture.ApiClientAsViewer.GetAsync("/v1/certificate-requests", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // ── UPDATE ─────────────────────────────────────────────────────────────────

    [Fact(DisplayName = "IT-CERT-UPDATE-001")]
    public async Task UpdateCertificateRequest_CannotChangeRequestedBy()
    {
        var cn = TestHelpers.UniqueCN();
        var createResp = await fixture.ApiClientAsAdmin.PostAsJsonAsync("/v1/certificate-requests",
            new { CommonName = cn, RequestedBy = "original-user", Type = "WebServer", PropertiesJson = "{}" }, TestContext.Current.CancellationToken);
        var created = await createResp.Content.ReadFromJsonAsync<CertificateRequest>(TestContext.Current.CancellationToken);
        Assert.NotNull(created);

        var putResp = await fixture.ApiClientAsAdmin.PutAsJsonAsync(
            $"/v1/certificate-requests/{created.Id}",
            new
            {
                CommonName = cn,
                RequestedBy = "updated-user",
                Type = "WebServer",
                PropertiesJson = "{}",
                Status = (int)CertificateRequestStatus.Pending
            }, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, putResp.StatusCode);
        var updated = await putResp.Content.ReadFromJsonAsync<CertificateRequest>(TestContext.Current.CancellationToken);
        Assert.NotNull(updated);
        // The requester comes from the token at creation time and is immutable thereafter, so
        // neither the create body's "original-user" nor the update body's "updated-user" is stored.
        Assert.Equal(created.RequestedBy, updated.RequestedBy);
        Assert.NotEqual("updated-user", updated.RequestedBy);
        Assert.True(updated.UpdatedAtUtc >= created.CreatedAtUtc);
    }

    [Fact(DisplayName = "IT-CERT-UPDATE-002")]
    public async Task UpdateCertificateRequest_AsViewer_Returns403()
    {
        var createResp = await fixture.ApiClientAsAdmin.PostAsJsonAsync("/v1/certificate-requests",
            new { CommonName = TestHelpers.UniqueCN(), RequestedBy = "r", Type = "WebServer", PropertiesJson = "{}" }, TestContext.Current.CancellationToken);
        var created = await createResp.Content.ReadFromJsonAsync<CertificateRequest>(TestContext.Current.CancellationToken);
        Assert.NotNull(created);

        var putResp = await fixture.ApiClientAsViewer.PutAsJsonAsync(
            $"/v1/certificate-requests/{created.Id}",
            new { created.CommonName, RequestedBy = "v", Type = "WebServer", PropertiesJson = "{}", Status = 0 }, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Forbidden, putResp.StatusCode);
    }

    // ── DELETE ─────────────────────────────────────────────────────────────────

    [Fact(DisplayName = "IT-CERT-DELETE-001")]
    public async Task DeleteCertificateRequest_Returns204_ThenGetReturns404()
    {
        var createResp = await fixture.ApiClientAsAdmin.PostAsJsonAsync("/v1/certificate-requests",
            new { CommonName = TestHelpers.UniqueCN(), RequestedBy = "r", Type = "WebServer", PropertiesJson = "{}" }, TestContext.Current.CancellationToken);
        var created = await createResp.Content.ReadFromJsonAsync<CertificateRequest>(TestContext.Current.CancellationToken);
        Assert.NotNull(created);

        var deleteResp = await fixture.ApiClientAsAdmin.DeleteAsync($"/v1/certificate-requests/{created.Id}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NoContent, deleteResp.StatusCode);

        var getResp = await fixture.ApiClientAsAdmin.GetAsync($"/v1/certificate-requests/{created.Id}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, getResp.StatusCode);
    }

    [Fact(DisplayName = "IT-CERT-DELETE-002")]
    public async Task DeleteCertificateRequest_NotFound_Returns404()
    {
        var response = await fixture.ApiClientAsAdmin.DeleteAsync($"/v1/certificate-requests/{Guid.NewGuid()}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact(DisplayName = "IT-CERT-DELETE-003")]
    public async Task DeleteCertificateRequest_AsViewer_Returns403()
    {
        var createResp = await fixture.ApiClientAsAdmin.PostAsJsonAsync("/v1/certificate-requests",
            new { CommonName = TestHelpers.UniqueCN(), RequestedBy = "r", Type = "WebServer", PropertiesJson = "{}" }, TestContext.Current.CancellationToken);
        var created = await createResp.Content.ReadFromJsonAsync<CertificateRequest>(TestContext.Current.CancellationToken);
        Assert.NotNull(created);

        var deleteResp = await fixture.ApiClientAsViewer.DeleteAsync($"/v1/certificate-requests/{created.Id}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, deleteResp.StatusCode);
    }
}
