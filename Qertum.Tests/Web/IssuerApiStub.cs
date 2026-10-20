using System.Net;
using System.Text;
using System.Text.Json;
using Qertum.Services;

namespace Qertum.Tests.Web;

/// <summary>Answers the issuer routes with canned JSON and records every request.</summary>
internal sealed class IssuerApiStub : HttpMessageHandler
{
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    public List<IssuerResponse> Issuers { get; } = [];
    public List<(HttpMethod Method, string Path, string? Body)> Requests { get; } = [];
    public Func<HttpRequestMessage, HttpResponseMessage?>? Override { get; set; }

    public static IssuerResponse Issuer(string name, IssuerStatus status = IssuerStatus.Active, IssuerKeyCustody custody = IssuerKeyCustody.Online,
        bool isDefault = false, IssuerKind kind = IssuerKind.Root, IssuerId? parent = null) =>
        new(new IssuerId(Guid.NewGuid()), name, kind, parent, custody, status, isDefault, $"CN={name}", "0A", "ECDSA-P384",
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(5), kind == IssuerKind.Intermediate ? 0 : null,
            kind == IssuerKind.Intermediate ? ["corp.example"] : [], [], [], [], null, null, DateTime.UtcNow, DateTime.UtcNow, null, null, null);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
        Requests.Add((request.Method, request.RequestUri!.AbsolutePath, body));
        if (Override?.Invoke(request) is { } overridden) return overridden;

        var path = request.RequestUri!.AbsolutePath;
        object? payload = path switch
        {
            "/v1/issuers" when request.Method == HttpMethod.Get => Issuers,
            _ when request.Method == HttpMethod.Post && path.StartsWith("/v1/issuers/", StringComparison.Ordinal) => Issuers.FirstOrDefault(),
            "/v1/ca/status" => new CaStatusResponse { IsInitialized = true },
            _ => Array.Empty<object>()
        };
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(payload, Web), Encoding.UTF8, "application/json")
        };
    }

    public static HttpResponseMessage Problem(HttpStatusCode status, string detail) =>
        new(status)
        {
            Content = new StringContent(JsonSerializer.Serialize(new { title = "Conflict", status = (int)status, detail }, Web),
                Encoding.UTF8, "application/problem+json")
        };
}
