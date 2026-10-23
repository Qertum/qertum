// Qertum.Tests/Cli/CliHelpCoverageTests.cs
using System.CommandLine;
using System.CommandLine.Completions;
using Qertum.Cli;

namespace Qertum.Tests.Cli;

/// <summary>
/// An LLM or a new user driving qca from --help alone must learn what a command needs, what it
/// changes, how it exits and how to call it. This walks the whole command tree; the standard applies to every command.
/// </summary>
public sealed class CliHelpCoverageTests
{
    private static readonly string[] StateChangingWords = ["Changes", "Creates", "Deletes", "Revokes", "Replaces", "Sets", "Signs", "Publishes", "Approves", "Denies", "Installs", "Uploads", "Archives", "Retires", "Enables", "Disables", "Resets"];

    private static IEnumerable<(string Path, Command Command)> Walk(Command root, string path)
    {
        foreach (var child in root.Subcommands)
        {
            var childPath = $"{path} {child.Name}";
            if (child.Subcommands.Count == 0) yield return (childPath, child);
            else
            {
                yield return (childPath, child);
                foreach (var nested in Walk(child, childPath)) yield return nested;
            }
        }
    }

    private static IEnumerable<string> Problems(string path, Command command)
    {
        if (string.IsNullOrWhiteSpace(command.Description)) { yield return $"{path}: no description"; yield break; }
        foreach (var option in command.Options.Where(o => string.IsNullOrWhiteSpace(o.Description)))
            yield return $"{path}: option {option.Name} has no description";
        foreach (var argument in command.Arguments.Where(a => string.IsNullOrWhiteSpace(a.Description)))
            yield return $"{path}: argument {argument.Name} has no description";

        if (command.Subcommands.Count > 0) yield break; // groups only need a description

        var lines = command.Description!.Split('\n').Select(l => l.Trim()).ToList();
        if (!lines.Any(l => l.StartsWith("Needs:", StringComparison.Ordinal))) yield return $"{path}: description has no 'Needs:' line";
        if (!lines.Any(l => l.StartsWith("Exit codes:", StringComparison.Ordinal))) yield return $"{path}: description has no 'Exit codes:' line";
        if (!lines.Any(l => l.StartsWith("Example:", StringComparison.Ordinal) && l.Contains("qca ", StringComparison.Ordinal)))
            yield return $"{path}: description has no 'Example: qca ...' line";
    }

    [Fact]
    public void EveryCommandMeetsTheHelpStandard()
    {
        var root = CliRoot.Build();
        var failures = new List<string>();

        foreach (var (path, command) in Walk(root, "qca"))
        {
            failures.AddRange(Problems(path, command));
        }

        Assert.True(failures.Count == 0, string.Join(Environment.NewLine, failures));
    }

    [Fact]
    public void FixedValueOptionsListTheirValuesInTheirDescription()
    {
        var root = CliRoot.Build();

        // Non-vacuity: the completion API must actually expose an AcceptOnlyFromAmong set.
        var status = Walk(root, "qca").Single(w => w.Path == "qca requests list").Command.Options.Single(o => o.Name == "--status");
        Assert.Contains("pending", status.GetCompletions(CompletionContext.Empty).Select(c => c.Label));

        var fixedValueOptionsSeen = 0;
        foreach (var (path, command) in Walk(root, "qca"))
            foreach (var option in command.Options.Where(o => o.ValueType != typeof(bool))) // flags complete to True/False, not a documented value set
            {
                var values = option.GetCompletions(CompletionContext.Empty).Select(c => c.Label).Where(v => !v.StartsWith('-')).ToList();
                if (values.Count == 0) continue;
                fixedValueOptionsSeen++;
                if (string.IsNullOrWhiteSpace(option.Description)) continue;
                Assert.All(values, v => Assert.True(option.Description!.Contains(v, StringComparison.OrdinalIgnoreCase),
                    $"{path} {option.Name}: description does not list '{v}'"));
            }

        Assert.True(fixedValueOptionsSeen > 0, "no fixed-value option was found anywhere in the tree; the check is vacuous");
    }

    [Fact]
    public void StateChangingCommandsSaySoInTheirDescription()
    {
        var readOnlyNames = new[] { "list", "show", "info", "status", "me", "versions", "history", "report", "activity", "inventory", "trust-bundle", "request", "doctor", "verify", "checkpoint" };
        foreach (var (path, command) in Walk(CliRoot.Build(), "qca"))
        {
            if (command.Subcommands.Count > 0) continue;
            if (readOnlyNames.Contains(command.Name)) continue;
            Assert.True(StateChangingWords.Any(w => command.Description!.Contains(w, StringComparison.Ordinal)),
                $"{path}: does not say what it changes (use one of: {string.Join(", ", StateChangingWords)})");
        }
    }

    [Theory]
    [InlineData("qca requests approve", "certificates.ca", "selfApproval")]
    [InlineData("qca requests create", "certificates.ca", "caPermission")]
    [InlineData("qca ca approval set", "admin", "waived")]
    [InlineData("qca ca strength set", "admin", "IssuerStrengthChanged")]
    public void TheFeatureCommandsExplainTheirCaRules(string path, params string[] mustMention)
    {
        var command = Walk(CliRoot.Build(), "qca").Single(w => w.Path == path).Command;
        Assert.All(mustMention, text => Assert.Contains(text, command.Description, StringComparison.Ordinal));
    }
}
