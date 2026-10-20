using System.Text.RegularExpressions;
using Qertum.Services;
using Qertum.Services.Lifecycle;

namespace Qertum.Tests.Lifecycle;

/// <summary>
/// Audit entries carry a ResourceId but not what kind of resource it names, so the table sink reads
/// the subject type from AuditActionSubjects. An action missing from the map would be dropped from
/// every timeline without a trace; this test finds every audited action in the source instead.
/// </summary>
public sealed partial class AuditActionSubjectsTests
{
    [Fact]
    public void EveryAuditedActionInTheSourceIsMapped()
    {
        var actions = AuditedActionsInSource();

        // Guards the scan itself: if the call-site shape changes, this fails instead of passing empty.
        // 41 audited actions exist on 2026-09-21; far fewer means the scan stopped matching.
        Assert.True(actions.Count >= 40, $"Found only {actions.Count} audited actions; the source scan no longer matches.");
        Assert.Empty(actions.Where(a => !AuditActionSubjects.IsKnown(a)).Order());
    }

    [Theory]
    [InlineData("Approved", LifecycleSubjectTypes.CertificateRequest)]
    [InlineData("PfxExported", LifecycleSubjectTypes.CertificateRequest)]
    [InlineData("IssuerKeyDownloaded", LifecycleSubjectTypes.Issuer)]
    [InlineData("IssuerPfxExported", LifecycleSubjectTypes.Issuer)]
    [InlineData("CertificateMetadataUpdated", LifecycleSubjectTypes.CertificateRequest)]
    [InlineData("ApprovalBlockedByPolicy", LifecycleSubjectTypes.CertificateRequest)]
    [InlineData("ApprovalPreviewed", LifecycleSubjectTypes.CertificateRequest)]
    [InlineData("TemplateCreated", LifecycleSubjectTypes.CertificateTemplate)]
    [InlineData("IssuancePolicyPublished", LifecycleSubjectTypes.IssuancePolicy)]
    [InlineData("AcmeExternalAccountKeyDisabled", LifecycleSubjectTypes.AcmeExternalAccountKey)]
    [InlineData("EstEnrollmentCredentialEnabled", LifecycleSubjectTypes.EstCredential)]
    [InlineData("WebhookDestinationRuleAdded", LifecycleSubjectTypes.WebhookDestinationRule)]
    [InlineData("WebhookDestinationRuleToggled", LifecycleSubjectTypes.WebhookDestinationRule)]
    [InlineData("WebhookDestinationRuleDeleted", LifecycleSubjectTypes.WebhookDestinationRule)]
    [InlineData("BulkOperationPreviewed", LifecycleSubjectTypes.BulkOperation)]
    [InlineData("BulkOperationCompleted", LifecycleSubjectTypes.BulkOperation)]
    public void MapsEachActionToTheKindOfResourceItsIdNames(string action, string expected)
    {
        Assert.Equal(expected, AuditActionSubjects.SubjectTypeOf(action));
    }

    [Theory]
    [InlineData("SettingsUpdated")]
    [InlineData("CaGenerationRequested")]
    [InlineData("RolePermissionsRenamed")]
    [InlineData("WebhookDestinationModeUpdated")]
    public void ActionsLoggedWithoutAResourceHaveNoSubject(string action)
    {
        Assert.True(AuditActionSubjects.IsKnown(action));
        Assert.Null(AuditActionSubjects.SubjectTypeOf(action));
    }

    private static HashSet<string> AuditedActionsInSource()
    {
        var root = FindRepoRoot();
        var actions = new HashSet<string>(StringComparer.Ordinal);
        string[] projects = ["Qertum.Services", "Qertum.ApiService", "Qertum.QueueConsumer", "Qertum.AcmeService", "Qertum.EstService"];
        foreach (var file in projects
                     .SelectMany(p => Directory.EnumerateFiles(Path.Combine(root, p), "*.cs", SearchOption.AllDirectories))
                     .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                              && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")))
        {
            var text = File.ReadAllText(file);
            foreach (Match call in LogAsyncCall().Matches(text))
            {
                var argument = call.Groups["arg"].Value.Trim();
                // The interface and implementation declare "string action"; they are not call sites.
                if (argument.StartsWith("string ", StringComparison.Ordinal)) continue;

                foreach (Match literal in StringLiteral().Matches(argument))
                    actions.Add(literal.Groups[1].Value);

                foreach (Match constant in WebhookEventConstant().Matches(argument))
                    actions.Add((string)typeof(WellKnownWebhookEvents).GetField(constant.Groups[1].Value)!.GetValue(null)!);

                // A bare local (LogAsync(action, …)): read the literals it is assigned from.
                if (Identifier().IsMatch(argument))
                    foreach (Match assignment in new Regex($@"var\s+{argument}\s*=\s*(?<expr>[^;]+);").Matches(text))
                        foreach (Match literal in StringLiteral().Matches(assignment.Groups["expr"].Value))
                            actions.Add(literal.Groups[1].Value);
            }
        }
        return actions;
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Qertum.sln")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Qertum.sln not found above the test binaries.");
    }

    [GeneratedRegex(@"\bLogAsync\(\s*(?<arg>[^,]+),")]
    private static partial Regex LogAsyncCall();

    [GeneratedRegex("\"([A-Za-z]+)\"")]
    private static partial Regex StringLiteral();

    [GeneratedRegex(@"WellKnownWebhookEvents\.([A-Za-z]+)")]
    private static partial Regex WebhookEventConstant();

    [GeneratedRegex(@"^[a-z][A-Za-z0-9]*$")]
    private static partial Regex Identifier();
}
