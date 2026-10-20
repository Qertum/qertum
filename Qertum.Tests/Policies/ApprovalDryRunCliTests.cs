using System.CommandLine;
using Qertum.Cli.Commands;
using Qertum.Services;

namespace Qertum.Tests.Policies;

public sealed class ApprovalDryRunCliTests
{
    private static Command Requests() => RequestsCommands.Build(
        new Option<string?>("--api-url"), new Option<string?>("--identity-url"),
        new Option<string?>("--token"), new Option<string>("--output"));

    // Parse errors cannot tell these apart: this command tree reports no error even for an unknown
    // option, so the tests read the declared options instead.
    [Fact]
    public void ApproveOffersDryRun()
    {
        var approve = Requests().Subcommands.Single(c => c.Name == "approve");
        var option = Assert.Single(approve.Options, o => o.Name == "--dry-run");

        var parsed = Requests().Parse($"approve --dry-run {Guid.NewGuid()} {Guid.NewGuid()}");

        Assert.Empty(parsed.Errors);
        Assert.True(parsed.GetValue<bool>(option.Name));
    }

    [Fact]
    public void DenyHasNoDryRun() =>
        Assert.DoesNotContain(Requests().Subcommands.Single(c => c.Name == "deny").Options, o => o.Name == "--dry-run");

    [Theory]
    [InlineData(new[] { true, true }, 0)]
    [InlineData(new[] { true, false }, 2)]
    public void ExitCode_FollowsTheVerdicts(bool[] verdicts, int expected) =>
        Assert.Equal(expected, RequestsCommands.ApprovalDryRunExitCode(verdicts.Select(v => (bool?)v)));

    [Fact]
    public void ExitCode_AFailedCallWins() =>
        Assert.Equal(1, RequestsCommands.ApprovalDryRunExitCode([false, null, true]));

    [Fact]
    public void PreviewLines_NameThePolicyOfTheEarlierEvaluation()
    {
        var id = Guid.Parse("11111111-2222-3333-4444-555555555555");
        var lines = RequestsCommands.ApprovalPreviewLines(id, new ApprovalPreviewResponse
        {
            Allowed = true, PolicyName = "Web servers", PolicyVersionNumber = 2,
            EvaluatedPolicyName = "Legacy", EvaluatedPolicyVersionNumber = 2, PolicyChangedSinceEvaluation = true
        });

        Assert.Equal(
        [
            $"admitted  {id}  (policy: Web servers v2)",
            "  last evaluated under policy 'Legacy' v2; the policy has changed since"
        ], lines);
    }

    [Fact]
    public void PreviewLines_SayRequesterRolesAreCheckedAtSubmission()
    {
        var id = Guid.NewGuid();
        var lines = RequestsCommands.ApprovalPreviewLines(id, new ApprovalPreviewResponse
        {
            Allowed = true, PolicyName = "Web servers", PolicyVersionNumber = 2, RequesterRolesCheckedAtSubmission = true
        }).ToList();

        Assert.Contains("  requester roles are checked at submission, not at approval", lines);
    }
}
