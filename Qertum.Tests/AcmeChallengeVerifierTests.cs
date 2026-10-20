using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Services.Acme;

namespace Qertum.Tests;

/// <summary>
/// End-to-end cover for the former IMPROVEMENTS.md audit §3.2: the address policy runs inside the socket connect
/// callback, so these exercise the real handler rather than the policy object in isolation. A test
/// that only called <see cref="IAcmeAddressPolicy"/> directly would still pass if the handler were
/// never wired up.
/// </summary>
public sealed class AcmeChallengeVerifierTests : IAsyncDisposable
{
    private readonly SqliteConnection _connection;
    private readonly ServiceProvider _provider;

    public AcmeChallengeVerifierTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        var services = new ServiceCollection();
        // AddAcmeServices binds AcmeDns01Options from configuration, which every real host has and
        // a bare ServiceCollection does not.
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().Build());
        services.AddLogging();
        services.AddDataProtection();
        services.AddDbContext<CertificateRequestDbContext>((sp, options) => options.UseSqlite(_connection));
        services.AddAcmeServices();

        _provider = services.BuildServiceProvider();

        using var scope = _provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>().Database.EnsureCreated();
    }

    private async Task SetAllowedNetworksAsync(string? json)
    {
        await using var scope = _provider.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();

        var settings = await db.Settings.SingleOrDefaultAsync(s => s.Id == 1);
        if (settings is null)
        {
            settings = new CaSettings { PqcStage = PqcStage.Off, Id = 1 };
            db.Settings.Add(settings);
        }

        settings.AcmeChallengeAllowedNetworksJson = json;
        await db.SaveChangesAsync();
    }

    private Task<AcmeVerificationResult> VerifyAsync(string domain) =>
        _provider.GetRequiredService<IAcmeChallengeVerifier>()
            .VerifyHttp01Async(domain, "test-token", "test-thumbprint", TestContext.Current.CancellationToken);

    [Fact]
    public async Task LoopbackIsBlockedWhenNoNetworksAreConfigured()
    {
        await SetAllowedNetworksAsync(null);

        // Port 1 is chosen so that a failure to block would surface as a connection error rather
        // than actually reaching a service.
        var (success, detail) = await VerifyAsync("localhost:1");

        Assert.False(success);
        Assert.Equal(AcmeAddressPolicy.NoNetworksConfigured, detail);
    }

    [Fact]
    public async Task LoopbackIsBlockedWhenTheAllowlistCoversOnlyOtherRanges()
    {
        await SetAllowedNetworksAsync("""["203.0.113.0/24"]""");

        var (success, detail) = await VerifyAsync("localhost:1");

        Assert.False(success);
        Assert.Contains("not in the configured allowed networks", detail);
    }

    [Fact]
    public async Task DeniedAddressReportsThePolicyReasonRatherThanATimeout()
    {
        await SetAllowedNetworksAsync("""["203.0.113.0/24"]""");

        var (_, detail) = await VerifyAsync("127.0.0.1:1");

        // The whole point of surfacing the reason: an operator debugging a failed order sees the
        // cause, not "Timeout reaching http://...".
        Assert.NotNull(detail);
        Assert.DoesNotContain("Timeout", detail);
        Assert.Contains("127.0.0.1", detail);
    }

    [Fact]
    public async Task MetadataAddressIsBlockedEvenWhenTheAllowlistCoversEverything()
    {
        await SetAllowedNetworksAsync("""["0.0.0.0/0"]""");

        var (success, detail) = await VerifyAsync("169.254.169.254");

        Assert.False(success);
        Assert.Contains("link-local", detail);
    }

    [Fact]
    public async Task AllowedLoopbackConnectsAndFailsOnTheResponseInstead()
    {
        // Proves the policy is not simply denying everything: with loopback permitted the request
        // proceeds to an actual connection attempt, which fails for a transport reason rather than
        // a policy reason.
        await SetAllowedNetworksAsync("""["127.0.0.0/8"]""");

        var (success, detail) = await VerifyAsync("127.0.0.1:1");

        Assert.False(success);
        Assert.NotNull(detail);
        Assert.DoesNotContain("allowed networks", detail);
        Assert.DoesNotContain("link-local", detail);
    }

    [Fact]
    public async Task AnAllowlistDenial_IsCategorizedAsAllowlistDenied()
    {
        await SetAllowedNetworksAsync("""["203.0.113.0/24"]""");

        var result = await VerifyAsync("127.0.0.1:1");

        Assert.Equal(AcmeChallengeFailure.AllowlistDenied, result.Failure);
    }

    [Fact]
    public async Task ARefusedConnection_IsCategorizedAsConnectionFailed()
    {
        await SetAllowedNetworksAsync("""["127.0.0.0/8"]""");

        var result = await VerifyAsync("127.0.0.1:1");

        Assert.Equal(AcmeChallengeFailure.ConnectionFailed, result.Failure);
    }

    [Fact]
    public async Task ANon200Answer_IsHttpStatus_AndTheDetailNeverCarriesTheToken()
    {
        // The detail is stored as a diagnostic event; the token proves control of the name and must
        // not be written anywhere the operator reads.
        await SetAllowedNetworksAsync("""["127.0.0.0/8"]""");
        var port = FreePort();
        using var listener = new System.Net.HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();
        var serve = Task.Run(async () =>
        {
            var context = await listener.GetContextAsync();
            context.Response.StatusCode = 404;
            context.Response.Close();
        }, TestContext.Current.CancellationToken);

        var result = await VerifyAsync($"127.0.0.1:{port}");
        await serve;

        Assert.False(result.Success);
        Assert.Equal(AcmeChallengeFailure.HttpStatus, result.Failure);
        Assert.Contains("404", result.ErrorDetail);
        Assert.DoesNotContain("test-token", result.ErrorDetail);
    }

    private static int FreePort()
    {
        var probe = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        probe.Start();
        var port = ((System.Net.IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }

    public async ValueTask DisposeAsync()
    {
        await _provider.DisposeAsync();
        await _connection.DisposeAsync();
    }
}
