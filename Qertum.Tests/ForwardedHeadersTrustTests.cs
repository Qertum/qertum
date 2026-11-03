using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Qertum.Tests;

/// <summary>
/// Behind a TLS proxy the deploy images switch on ASPNETCORE_FORWARDEDHEADERS_ENABLED for web, identity and API. That
/// switch alone trusts X-Forwarded-Proto and X-Forwarded-For from every client, so anyone reaching a published port
/// directly could claim https or any address. The headers are now honoured only from ForwardedHeaders:TrustedProxies
/// (QERTUM_TRUSTED_PROXIES), and a host with the switch on and no trusted proxy refuses to start. Checked against the
/// real identity provider, whose discovery document shows which scheme it believed.
/// </summary>
public sealed class ForwardedHeadersTrustTests : IDisposable
{
    private const string Authority = "https://idp.test";
    private readonly string _dataPath = Path.Combine(Path.GetTempPath(), "qertum-fwd-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(_dataPath, recursive: true); } catch (IOException) { /* best effort */ }
    }

    [Theory]
    [InlineData("172.18.0.0/16", "172.18.0.5", "https")]
    [InlineData("172.18.0.0/16", "203.0.113.9", "http")]
    // Kestrel on a dual-stack socket reports an IPv4 peer as IPv4-mapped IPv6; an IPv4 entry must still match it.
    [InlineData("172.18.0.0/16", "::ffff:172.18.0.5", "https")]
    [InlineData("10.1.2.3", "10.1.2.3", "https")]
    [InlineData("10.1.2.3, 192.168.5.0/24", "192.168.5.20", "https")]
    [InlineData("10.1.2.3", "10.1.2.4", "http")]
    public async Task ForwardedProto_IsHonouredOnlyFromATrustedProxy(string trusted, string remote, string expectedScheme)
    {
        using var factory = CreateFactory(trusted);
        _ = factory.CreateClient();

        var context = await factory.Server.SendAsync(c =>
        {
            c.Request.Method = HttpMethods.Get;
            c.Request.Path = "/.well-known/openid-configuration";
            c.Request.Host = new HostString("idp.test");
            c.Request.Headers["X-Forwarded-Proto"] = "https";
            c.Connection.RemoteIpAddress = IPAddress.Parse(remote);
        }, TestContext.Current.CancellationToken);

        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        var document = await JsonDocument.ParseAsync(context.Response.Body, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal($"{expectedScheme}://idp.test/connect/token", document.RootElement.GetProperty("token_endpoint").GetString());
    }

    [Fact]
    public void ForwardedHeadersWithoutATrustedProxy_StopTheHostAtStartup()
    {
        using var factory = CreateFactory(trusted: null);

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains("QERTUM_TRUSTED_PROXIES", Flatten(ex));
    }

    private static string Flatten(Exception ex) =>
        ex is AggregateException or OptionsValidationException || ex.InnerException is null
            ? ex.ToString()
            : ex.Message + Flatten(ex.InnerException);

    private WebApplicationFactory<IdentityServiceProgram> CreateFactory(string? trusted) =>
        ConfiguredFactory.Create<IdentityServiceProgram>(builder =>
        {
            builder.UseEnvironment(Environments.Production);
            builder.UseSetting("IdentityService:Authority", Authority);
            builder.UseSetting("IdentityService:DataPath", _dataPath);
            builder.UseSetting("IdentityService:DisableTransportSecurity", "true");
            builder.UseSetting("ConnectionStrings:Identity", $"Data Source={Path.Combine(_dataPath, "identity.db")}");
            // The configuration key behind ASPNETCORE_FORWARDEDHEADERS_ENABLED.
            builder.UseSetting("ForwardedHeaders_Enabled", "true");
            if (trusted is not null)
                builder.UseSetting("ForwardedHeaders:TrustedProxies", trusted);
        });
}
