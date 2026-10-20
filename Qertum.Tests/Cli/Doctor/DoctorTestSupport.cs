using System.Net;
using System.Text;
using Microsoft.Extensions.Time.Testing;
using Qertum.Cli.Doctor;

namespace Qertum.Tests.Cli.Doctor;

/// <summary>A request the fake saw: its URL and the Authorization header it carried, if any.</summary>
internal sealed record SeenRequest(string Url, string? Authorization);

/// <summary>Answers requests from a route table. An unknown URL is a 404; every request is recorded.</summary>
internal sealed class FakeHttp : HttpMessageHandler
{
    private readonly Dictionary<string, Func<CancellationToken, Task<HttpResponseMessage>>> _routes = new(StringComparer.Ordinal);

    public List<SeenRequest> Seen { get; } = [];

    public FakeHttp Route(string url, HttpStatusCode status, string body = "", string contentType = "application/json", string? location = null)
    {
        _routes[url] = _ =>
        {
            var response = new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, contentType) };
            if (location is not null) response.Headers.Location = new Uri(location, UriKind.RelativeOrAbsolute);
            return Task.FromResult(response);
        };
        return this;
    }

    public FakeHttp RouteBytes(string url, HttpStatusCode status, byte[] body, string contentType = "application/octet-stream")
    {
        _routes[url] = _ =>
        {
            var content = new ByteArrayContent(body);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(contentType);
            return Task.FromResult(new HttpResponseMessage(status) { Content = content });
        };
        return this;
    }

    public FakeHttp Throw(string url, Exception exception)
    {
        _routes[url] = _ => throw exception;
        return this;
    }

    /// <summary>Never answers; only the caller's cancellation (the probe timeout) ends it.</summary>
    public FakeHttp Hang(string url)
    {
        _routes[url] = async ct =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, ct);
            return new HttpResponseMessage(HttpStatusCode.OK);
        };
        return this;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var url = request.RequestUri!.ToString();
        lock (Seen) Seen.Add(new SeenRequest(url, request.Headers.Authorization?.ToString()));
        return _routes.TryGetValue(url, out var route)
            ? await route(cancellationToken)
            : new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("") };
    }
}

internal sealed class FakeRootStore(RootStoreAnswer answer = RootStoreAnswer.Installed) : IRootStore
{
    public List<string> Looked { get; } = [];

    public RootStoreAnswer Lookup(string sha256Hex)
    {
        Looked.Add(sha256Hex);
        return answer;
    }
}

internal static class DoctorTestSupport
{
    public static readonly DateTimeOffset Now = new(2026, 10, 7, 12, 0, 0, TimeSpan.Zero);

    public static DoctorContext Context(
        FakeHttp http, string? apiUrl = "https://ca.test", string? identityUrl = "https://id.test", string? token = "tok",
        IRootStore? roots = null, TimeSpan? timeout = null, string? tokenProblem = null) =>
        new()
        {
            ApiUrl = apiUrl,
            IdentityUrl = identityUrl,
            Token = token,
            TokenProblem = token is null ? tokenProblem ?? "not logged in" : null,
            Handler = http,
            Clock = new FakeTimeProvider(Now),
            RootStore = roots ?? new FakeRootStore(),
            Timeout = timeout ?? TimeSpan.FromSeconds(5)
        };
}
