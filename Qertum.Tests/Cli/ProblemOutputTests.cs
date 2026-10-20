using System.Net;
using Qertum.Services;
using Qertum.Cli.Api;

namespace Qertum.Tests.Cli;

public sealed class ProblemOutputTests
{
    private static ApiProblemException Problem(HttpStatusCode status, string? correlationId, params IssuancePolicyViolation[] violations) =>
        new(status, "Title", "the detail", null, null, violations, correlationId);

    [Fact]
    public void AnError_PrintsTheStatusAndDetail_ThenTheCorrelationId()
    {
        var lines = CliApi.FormatProblem(Problem(HttpStatusCode.InternalServerError, "4bf92f3577b34da6a3ce929d0e0e4736"), forbiddenHint: null);

        Assert.Equal(["error: 500 — the detail", "  correlation id: 4bf92f3577b34da6a3ce929d0e0e4736"], lines);
    }

    [Fact]
    public void WithoutAnId_ThereIsNoCorrelationLine()
    {
        var lines = CliApi.FormatProblem(Problem(HttpStatusCode.NotFound, null), forbiddenHint: null);

        Assert.Equal(["error: 404 — the detail"], lines);
    }

    [Fact]
    public void AForbiddenCall_KeepsItsHint_AndStillShowsTheId()
    {
        var lines = CliApi.FormatProblem(Problem(HttpStatusCode.Forbidden, "abc"), forbiddenHint: "needs settings.edit");

        Assert.Equal(["error: 403 — the detail (needs settings.edit)", "  correlation id: abc"], lines);
    }

    [Fact]
    public void PolicyViolations_ComeBeforeTheCorrelationId()
    {
        var violation = new IssuancePolicyViolation("keyAlgorithm", "RSA-1024", "key too small");

        var lines = CliApi.FormatProblem(Problem(HttpStatusCode.BadRequest, "abc", violation), forbiddenHint: null);

        Assert.Equal(["error: 400 — the detail", "  - key too small", "  correlation id: abc"], lines);
    }

    [Fact]
    public void AStepUpRefusal_SaysWhatIsNeeded_AndTheExactCommand()
    {
        var ex = new ApiProblemException(HttpStatusCode.Unauthorized, "Step-up authentication required", "The last sign-in is too old for this operation.",
            null, null, [], "abc", new StepUpChallenge("mfa", 300));

        var lines = CliApi.FormatProblem(ex, forbiddenHint: null);

        Assert.Equal(
        [
            "error: 401 — The last sign-in is too old for this operation.",
            "  this operation needs a recent second-factor sign-in",
            "  run: qca auth login --acr-values mfa --max-age 300  (if your identity provider honours them in the device flow; if the token does not change, sign in with a second factor through the provider itself)",
            "  correlation id: abc"
        ], lines);
    }

    [Fact]
    public void AStepUpRefusalWithoutParameters_StillSuggestsLogin()
    {
        var ex = new ApiProblemException(HttpStatusCode.Unauthorized, "t", "d", null, null, [], null, new StepUpChallenge(null, null));

        Assert.Contains(CliApi.FormatProblem(ex, forbiddenHint: null), l => l.StartsWith("  run: qca auth login", StringComparison.Ordinal));
    }
}
