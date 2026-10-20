namespace Qertum.Tests.IdpInterop;

public sealed class TotpTests
{
    [Fact]
    public void MatchesTheRfc6238Vector() =>
        Assert.Equal("287082", Totp.Code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", DateTimeOffset.FromUnixTimeSeconds(59)));

    [Fact]
    public void TheNextWindowOffset_GivesADifferentCode() =>
        Assert.NotEqual(Totp.Code("JBSWY3DPEHPK3PXP", DateTimeOffset.FromUnixTimeSeconds(1_000_000)),
                        Totp.Code("JBSWY3DPEHPK3PXP", DateTimeOffset.FromUnixTimeSeconds(1_000_000), 1));
}
