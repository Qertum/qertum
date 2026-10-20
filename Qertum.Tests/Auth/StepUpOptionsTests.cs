using Qertum.Services.Auth;

namespace Qertum.Tests.Auth;

public sealed class StepUpOptionsTests
{
    [Fact]
    public void Defaults_AreOff_Mfa_FiveMinutes_AndStandardClaimNames()
    {
        var o = new StepUpOptions();

        Assert.False(o.Enabled);
        Assert.Equal(["mfa"], o.AcceptedAcrValues);
        Assert.Equal(300, o.MaxAgeSeconds);
        Assert.Equal("acr", o.AcrClaimType);
        Assert.Equal("auth_time", o.AuthTimeClaimType);
    }

    [Fact]
    public void AcrValues_AreSplitOnCommas_Trimmed_AndDeduplicated()
    {
        var o = new StepUpOptions { AcrValues = " mfa , urn:okta:loa:2fa:any,,mfa " };

        Assert.Equal(["mfa", "urn:okta:loa:2fa:any"], o.AcceptedAcrValues);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    [InlineData(86_401)]
    public void MaxAgeOutsideOneToADay_IsRejected_EvenWhenDisabled(int seconds)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => new StepUpOptions { MaxAgeSeconds = seconds }.Validate());

        Assert.Contains("Identity:StepUp:MaxAgeSeconds", ex.Message);
    }

    [Fact]
    public void Enabled_WithNoAcrValues_IsRejected()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => new StepUpOptions { Enabled = true, AcrValues = " , " }.Validate());

        Assert.Contains("Identity:StepUp:AcrValues", ex.Message);
    }

    [Theory]
    [InlineData("mfa\"")]
    [InlineData("a\\b")]
    [InlineData("two words")]
    [InlineData("tab\tvalue")]
    public void AnAcrValueThatCouldBreakTheChallengeHeaderOrTheCliHint_IsRejected(string value)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => new StepUpOptions { Enabled = true, AcrValues = value }.Validate());

        Assert.Contains("Identity:StepUp:AcrValues", ex.Message);
    }

    [Fact]
    public void UrisAndUrnsAreFineAsAcrValues() =>
        new StepUpOptions { Enabled = true, AcrValues = "urn:okta:loa:2fa:any,http://schemas.openid.net/pape/policies/2007/06/multi-factor" }.Validate();

    [Theory]
    [InlineData("", "auth_time", "AcrClaimType")]
    [InlineData("acr", " ", "AuthTimeClaimType")]
    public void EmptyClaimNames_AreRejected(string acr, string authTime, string key)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => new StepUpOptions { AcrClaimType = acr, AuthTimeClaimType = authTime }.Validate());

        Assert.Contains($"Identity:StepUp:{key}", ex.Message);
    }

    [Fact]
    public void TheIdentityOptions_ValidateTheStepUpSection_EvenInDevelopment()
    {
        var options = new IdentityAuthenticationOptions { Authority = "https://idp.example", StepUp = { MaxAgeSeconds = 0 } };

        Assert.Throws<InvalidOperationException>(() => options.Validate(isDevelopment: true));
    }
}
