using System.Security.Claims;
using Microsoft.Extensions.Time.Testing;
using Qertum.Services.Auth;

namespace Qertum.Tests.Auth;

public sealed class StepUpEvaluatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 15, 12, 0, 0, TimeSpan.Zero);
    private static long Unix(DateTimeOffset t) => t.ToUnixTimeSeconds();

    private static StepUpEvaluator Evaluator(StepUpOptions? options = null) =>
        new(options ?? new StepUpOptions { Enabled = true, AcrValues = "mfa,urn:loa:2", MaxAgeSeconds = 300 }, new FakeTimeProvider(Now));

    private static ClaimsPrincipal User(params (string Type, string Value)[] claims) =>
        new(new ClaimsIdentity(claims.Select(c => new Claim(c.Type, c.Value)), "test"));

    private static StepUpResult Evaluate(params (string Type, string Value)[] claims) => Evaluator().Evaluate(User(claims));

    [Fact]
    public void Disabled_AlwaysSucceeds_EvenForAnEmptyPrincipal()
    {
        var evaluator = Evaluator(new StepUpOptions { Enabled = false });

        Assert.Equal(StepUpResult.Satisfied, evaluator.Evaluate(User()));
    }

    [Fact]
    public void AListedAcr_WithAFreshAuthTime_Succeeds()
    {
        Assert.Equal(StepUpResult.Satisfied, Evaluate(("acr", "mfa"), ("auth_time", Unix(Now.AddSeconds(-10)).ToString())));
    }

    [Fact]
    public void AnyListedAcr_AmongSeveralClaims_Succeeds()
    {
        Assert.Equal(StepUpResult.Satisfied,
            Evaluate(("acr", "pwd"), ("acr", "urn:loa:2"), ("auth_time", Unix(Now).ToString())));
    }

    [Fact]
    public void NoAcrClaim_IsRefused() =>
        Assert.Equal(StepUpResult.NoAcr, Evaluate(("auth_time", Unix(Now).ToString())));

    [Theory]
    [InlineData("pwd")]
    [InlineData("MFA")]
    [InlineData("mfa ")]
    [InlineData("")]
    public void AnUnlistedAcr_IsRefused_AndTheComparisonIsCaseSensitive(string acr) =>
        Assert.Equal(StepUpResult.WrongAcr, Evaluate(("acr", acr), ("auth_time", Unix(Now).ToString())));

    [Fact]
    public void NoAuthTime_IsRefused() =>
        Assert.Equal(StepUpResult.NoAuthTime, Evaluate(("acr", "mfa")));

    [Theory]
    [InlineData("yesterday")]
    [InlineData("1.79e9")]
    [InlineData("1792014128.5")]
    [InlineData("-1")]
    [InlineData("99999999999999999999")]
    [InlineData("")]
    public void AnAuthTimeThatIsNotAWholeUnixTimestamp_IsRefused(string value) =>
        Assert.Equal(StepUpResult.BadAuthTime, Evaluate(("acr", "mfa"), ("auth_time", value)));

    [Fact]
    public void ExactlyMaxAgeOld_Passes_AndOneSecondMore_IsStale()
    {
        Assert.Equal(StepUpResult.Satisfied, Evaluate(("acr", "mfa"), ("auth_time", Unix(Now.AddSeconds(-300)).ToString())));
        Assert.Equal(StepUpResult.Stale, Evaluate(("acr", "mfa"), ("auth_time", Unix(Now.AddSeconds(-301)).ToString())));
    }

    [Fact]
    public void FutureDatedBeyondThirtySeconds_IsRefused_ButSmallSkewIsTolerated()
    {
        Assert.Equal(StepUpResult.Satisfied, Evaluate(("acr", "mfa"), ("auth_time", Unix(Now.AddSeconds(30)).ToString())));
        Assert.Equal(StepUpResult.AuthTimeInFuture, Evaluate(("acr", "mfa"), ("auth_time", Unix(Now.AddSeconds(31)).ToString())));
    }

    [Fact]
    public void CustomClaimNames_AreHonoured()
    {
        var evaluator = Evaluator(new StepUpOptions { Enabled = true, AcrValues = "gold", AcrClaimType = "loa", AuthTimeClaimType = "signed_in_at" });

        Assert.Equal(StepUpResult.Satisfied, evaluator.Evaluate(User(("loa", "gold"), ("signed_in_at", Unix(Now).ToString()))));
        Assert.Equal(StepUpResult.NoAcr, evaluator.Evaluate(User(("acr", "gold"), ("auth_time", Unix(Now).ToString()))));
    }

    [Fact]
    public void EveryRefusal_HasADescription_ThatNeverEchoesAClaimValue()
    {
        foreach (var result in Enum.GetValues<StepUpResult>().Where(r => r != StepUpResult.Satisfied))
        {
            var text = StepUpEvaluator.Describe(result);
            Assert.False(string.IsNullOrWhiteSpace(text));
            Assert.DoesNotContain("{", text);
        }
    }
}
