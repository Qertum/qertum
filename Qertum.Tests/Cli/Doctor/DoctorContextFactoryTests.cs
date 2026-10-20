using System.Text;
using Microsoft.Extensions.Time.Testing;
using Qertum.Cli.Auth;
using Qertum.Cli.Doctor;

namespace Qertum.Tests.Cli.Doctor;

public sealed class DoctorContextFactoryTests
{
    private static readonly DateTimeOffset Now = DoctorTestSupport.Now;

    private static string Jwt(DateTimeOffset? exp)
    {
        static string B64(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var payload = exp is null ? "{\"sub\":\"alice\"}" : $"{{\"sub\":\"alice\",\"exp\":{exp.Value.ToUnixTimeSeconds()}}}";
        return $"{B64("{\"alg\":\"none\"}")}.{B64(payload)}.sig";
    }

    private static CachedSession Session(DateTimeOffset expiresAt, string token = "cached-token") => new()
    {
        AccessToken = token, ExpiresAt = expiresAt, ApiUrl = "https://cached-api.test/", IdentityUrl = "https://cached-id.test/", Username = "alice"
    };

    private static DoctorContext Create(DoctorInputs inputs, CachedSession? cached, out int loads)
    {
        var count = 0;
        var context = DoctorContextFactory.Create(inputs, () => { count++; return cached; }, new FakeHttp(),
            new FakeTimeProvider(Now), new FakeRootStore(), TimeSpan.FromSeconds(7));
        loads = count;
        return context;
    }

    [Fact]
    public void ACachedSession_SuppliesUrlsAndToken_WithTheTrailingSlashTrimmed()
    {
        var context = Create(new DoctorInputs(null, null, null), Session(Now.AddHours(1)), out _);

        Assert.Equal("https://cached-api.test", context.ApiUrl);
        Assert.Equal("https://cached-id.test", context.IdentityUrl);
        Assert.Equal("cached-token", context.Token);
        Assert.Null(context.TokenProblem);
        Assert.Equal(TimeSpan.FromSeconds(7), context.Timeout);
    }

    [Fact]
    public void ExplicitInputs_WinOverTheCache()
    {
        var context = Create(new DoctorInputs("https://flag-api.test/qertum/", "https://flag-id.test", "flag-token"), Session(Now.AddHours(1)), out _);

        Assert.Equal("https://flag-api.test/qertum", context.ApiUrl);
        Assert.Equal("https://flag-id.test", context.IdentityUrl);
        Assert.Equal("flag-token", context.Token);
    }

    [Fact]
    public void AnExpiredCachedSession_HasNoToken_AndSaysWhy_AndIsNeverRefreshedOrCleared()
    {
        var context = Create(new DoctorInputs(null, null, null), Session(Now.AddMinutes(-1)), out var loads);

        Assert.Null(context.Token);
        Assert.Contains("expired", context.TokenProblem, StringComparison.Ordinal);
        Assert.Contains("qca auth login", context.TokenProblem, StringComparison.Ordinal);
        Assert.Equal(1, loads); // the one read; the factory is given no way to write or clear
        Assert.Equal("https://cached-api.test", context.ApiUrl);
    }

    [Fact]
    public void NoSessionAndNoToken_IsNotLoggedIn()
    {
        var context = Create(new DoctorInputs("https://api.test", null, null), null, out _);

        Assert.Null(context.Token);
        Assert.Contains("not logged in", context.TokenProblem, StringComparison.Ordinal);
        Assert.Equal("https://api.test", context.ApiUrl);
        Assert.Null(context.IdentityUrl);
    }

    [Fact]
    public void AnExplicitJwt_IsJudgedByItsOwnExpiry()
    {
        var expired = Create(new DoctorInputs("https://a.test", null, Jwt(Now.AddMinutes(-5))), null, out _);
        var valid = Create(new DoctorInputs("https://a.test", null, Jwt(Now.AddMinutes(5))), null, out _);
        var opaque = Create(new DoctorInputs("https://a.test", null, "opaque-token"), null, out _);

        Assert.Null(expired.Token);
        Assert.Contains("expired", expired.TokenProblem, StringComparison.Ordinal);
        Assert.NotNull(valid.Token);
        Assert.Equal("opaque-token", opaque.Token); // no exp claim: the server decides
    }

    [Theory]
    [InlineData("   ")]
    [InlineData("")]
    [InlineData(null)]
    public void BlankUrls_AreTreatedAsMissing(string? blank)
    {
        var context = Create(new DoctorInputs(blank, blank, null), null, out _);

        Assert.Null(context.ApiUrl);
        Assert.Null(context.IdentityUrl);
    }

    [Fact]
    public void ExtractExpiry_ReadsExp_AndIsNullForAnythingElse()
    {
        Assert.Equal(Now.ToUnixTimeSeconds(), JwtPayload.ExtractExpiry(Jwt(Now))!.Value.ToUnixTimeSeconds());
        Assert.Null(JwtPayload.ExtractExpiry(Jwt(null)));
        Assert.Null(JwtPayload.ExtractExpiry("not-a-jwt"));
        Assert.Null(JwtPayload.ExtractExpiry("a.!!!.c"));
    }
}
