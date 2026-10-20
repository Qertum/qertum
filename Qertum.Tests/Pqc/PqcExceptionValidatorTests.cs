using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Qertum.Services;
using Qertum.Services.Validators;

namespace Qertum.Tests.Pqc;

public sealed class PqcExceptionValidatorTests
{
    private static readonly DateTime Now = new(2026, 9, 29, 12, 0, 0, DateTimeKind.Utc);

    private static CreatePqcExceptionRequestValidator Validator(int maxDays = 365) =>
        new(Options.Create(new PqcExceptionOptions { MaxDays = maxDays }), new FakeTimeProvider(new DateTimeOffset(Now)));

    private static CreatePqcExceptionRequest Valid(Action<CreatePqcExceptionRequest>? change = null)
    {
        var request = new CreatePqcExceptionRequest
        {
            TemplateTypeKey = "WebServer", NamePattern = "legacy.corp.example", Family = PqcExceptionFamily.Rsa,
            ExpiresAtUtc = Now.AddDays(30), Reason = "old load balancer"
        };
        change?.Invoke(request);
        return request;
    }

    private static bool Passes(CreatePqcExceptionRequest request, int maxDays = 365) =>
        Validator(maxDays).Validate(request).IsValid;

    [Fact] public void AValidRequest_Passes() => Assert.True(Passes(Valid()));

    [Fact] public void TrailingDotAndMixedCase_Pass() =>
        Assert.True(Passes(Valid(r => r.NamePattern = "Legacy.Corp.Example.")));

    [Theory]
    [InlineData("")]
    [InlineData("*.corp.example")]
    [InlineData("10.0.0.1")]
    [InlineData("has space.example")]
    public void BadNamePatterns_Fail(string pattern) => Assert.False(Passes(Valid(r => r.NamePattern = pattern)));

    [Fact] public void ATooLongNamePattern_Fails() =>
        Assert.False(Passes(Valid(r => r.NamePattern = new string('a', 250) + ".example")));

    [Fact] public void AnEmptyReason_Fails() => Assert.False(Passes(Valid(r => r.Reason = "")));

    [Fact] public void ATooLongReason_Fails() => Assert.False(Passes(Valid(r => r.Reason = new string('x', 501))));

    [Fact] public void ExpiryInThePast_Fails() => Assert.False(Passes(Valid(r => r.ExpiresAtUtc = Now.AddMinutes(-1))));

    [Fact] public void ExpiryEqualToNow_Fails() => Assert.False(Passes(Valid(r => r.ExpiresAtUtc = Now)));

    [Fact] public void ExpiryBeyondMaxDays_Fails() =>
        Assert.False(Passes(Valid(r => r.ExpiresAtUtc = Now.AddDays(365).AddTicks(1))));

    [Fact] public void ExpiryExactlyAtMaxDays_Passes() =>
        Assert.True(Passes(Valid(r => r.ExpiresAtUtc = Now.AddDays(365))));

    [Fact] public void LocalTimeExpiry_Fails() =>
        Assert.False(Passes(Valid(r => r.ExpiresAtUtc = DateTime.SpecifyKind(Now.AddDays(5), DateTimeKind.Local))));

    [Fact] public void AnUndefinedFamily_Fails() =>
        Assert.False(Passes(Valid(r => r.Family = (PqcExceptionFamily)99)));
}
