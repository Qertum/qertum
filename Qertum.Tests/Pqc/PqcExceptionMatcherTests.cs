using Qertum.Services;

namespace Qertum.Tests.Pqc;

public sealed class PqcExceptionMatcherTests
{
    private static readonly DateTime Now = new(2026, 9, 29, 12, 0, 0, DateTimeKind.Utc);

    private static PqcException Exception(string pattern = "legacy.corp.example",
        PqcExceptionFamily family = PqcExceptionFamily.Rsa, string template = "WebServer",
        DateTime? expires = null, DateTime? revoked = null) => new()
    {
        TemplateTypeKey = template, NamePattern = pattern, Family = family,
        ExpiresAtUtc = expires ?? Now.AddDays(30), RevokedAtUtc = revoked
    };

    private static bool Matches(PqcException e, string[] names, string template = "WebServer",
        CertificateKeyAlgorithm? algorithm = null, bool nonDns = false) =>
        PqcExceptionMatcher.Matches(e, template, algorithm ?? CertificateKeyAlgorithm.Rsa, names, nonDns, Now);

    [Fact] public void ExactName_Matches() =>
        Assert.True(Matches(Exception(), ["legacy.corp.example"]));

    [Fact] public void SubdomainOfPattern_Matches() =>
        Assert.True(Matches(Exception(), ["a.legacy.corp.example"]));

    [Fact] public void TrailingDotAndCase_AreNormalised() =>
        Assert.True(Matches(Exception("Legacy.Corp.Example."), ["LEGACY.corp.example."]));

    [Fact] public void WildcardName_IsJudgedByItsBase() =>
        Assert.True(Matches(Exception("corp.example"), ["*.corp.example"]));

    [Fact] public void OneUncoveredName_MeansNoMatch() =>
        Assert.False(Matches(Exception(), ["legacy.corp.example", "other.corp.example"]));

    [Fact] public void AnyNonDnsSan_MeansNoMatch() =>
        Assert.False(Matches(Exception(), ["legacy.corp.example"], nonDns: true));

    [Fact] public void NoNames_MeansNoMatch() =>
        Assert.False(Matches(Exception(), []));

    [Fact] public void WrongTemplate_DoesNotMatch() =>
        Assert.False(Matches(Exception(), ["legacy.corp.example"], template: "ClientAuth"));

    [Fact] public void WrongFamily_DoesNotMatch() =>
        Assert.False(Matches(Exception(family: PqcExceptionFamily.Ecdsa), ["legacy.corp.example"]));

    [Fact] public void EcdsaException_MatchesBothCurves()
    {
        var e = Exception(family: PqcExceptionFamily.Ecdsa);
        Assert.True(Matches(e, ["legacy.corp.example"], algorithm: CertificateKeyAlgorithm.EcdsaP256));
        Assert.True(Matches(e, ["legacy.corp.example"], algorithm: CertificateKeyAlgorithm.EcdsaP384));
    }

    [Fact] public void ExpiryEqualToNow_IsInactive() =>
        Assert.False(Matches(Exception(expires: Now), ["legacy.corp.example"]));

    [Fact] public void OneTickBeforeExpiry_IsActive() =>
        Assert.True(Matches(Exception(expires: Now.AddTicks(1)), ["legacy.corp.example"]));

    [Fact] public void Revoked_IsInactive() =>
        Assert.False(Matches(Exception(revoked: Now.AddMinutes(-1)), ["legacy.corp.example"]));

    [Fact] public void UnrelatedNameWithSameSuffixText_DoesNotMatch() =>
        Assert.False(Matches(Exception(), ["notlegacy.corp.example"]));
}
