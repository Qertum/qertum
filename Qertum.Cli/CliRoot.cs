using System.CommandLine;
using Qertum.Cli.Commands;

namespace Qertum.Cli;

/// <summary>Builds the <c>qca</c> command tree. Separate from Program so tests can walk it.</summary>
internal static class CliRoot
{
    /// <summary>Creates the root command with global options and every command group.</summary>
    public static RootCommand Build()
    {
        // Global options — each carries an env-var fallback documented in the description.
        var apiUrlOption = new Option<string?>("--api-url")
        {
            Description = "API service base URL (or set QERTUM_API_URL)",
            Recursive = true
        };
        apiUrlOption.Aliases.Add("-a");

        var identityUrlOption = new Option<string?>("--identity-url")
        {
            Description = "Identity service base URL (or set QERTUM_IDENTITY_URL)",
            Recursive = true
        };
        identityUrlOption.Aliases.Add("-i");

        var tokenOption = new Option<string?>("--token")
        {
            Description = "Bearer token (bypasses cached session; or set QERTUM_TOKEN)",
            Recursive = true
        };
        tokenOption.Aliases.Add("-t");

        var outputOption = new Option<string>("--output")
        {
            Description = "Output format: table, json",
            DefaultValueFactory = _ => "table",
            Recursive = true
        };
        outputOption.Aliases.Add("-o");
        outputOption.AcceptOnlyFromAmong("table", "json");

        var rootCommand = new RootCommand("qca — CLI for the Qertum Certificate Authority");
        rootCommand.Options.Add(apiUrlOption);
        rootCommand.Options.Add(identityUrlOption);
        rootCommand.Options.Add(tokenOption);
        rootCommand.Options.Add(outputOption);

        rootCommand.Subcommands.Add(AuthCommands.Build(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        rootCommand.Subcommands.Add(CaCommands.Build(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        rootCommand.Subcommands.Add(BulkCommands.Build(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        rootCommand.Subcommands.Add(RootCommands.Build());
        rootCommand.Subcommands.Add(IssuerCommands.Build(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        rootCommand.Subcommands.Add(CertCommands.Build(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        rootCommand.Subcommands.Add(ApprovalCommands.Build(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        rootCommand.Subcommands.Add(NoticeCommands.Build(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        rootCommand.Subcommands.Add(RequestsCommands.Build(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        rootCommand.Subcommands.Add(AuditCommands.Build(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        rootCommand.Subcommands.Add(WebhookCommands.Build(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        rootCommand.Subcommands.Add(AcmeCommands.Build(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        rootCommand.Subcommands.Add(PolicyCommands.Build(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        rootCommand.Subcommands.Add(EstCommands.Build(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        rootCommand.Subcommands.Add(PermissionCommands.Build(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        rootCommand.Subcommands.Add(DoctorCommands.Build(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        rootCommand.Subcommands.Add(PqcCommands.Build(apiUrlOption, identityUrlOption, tokenOption, outputOption));

        return rootCommand;
    }
}
