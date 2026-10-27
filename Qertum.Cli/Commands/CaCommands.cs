using System.CommandLine;
using Qertum.Cli.Api;
using Qertum.Cli.Auth;
using Qertum.Services;

namespace Qertum.Cli.Commands;

internal static class CaCommands
{
    public static Command Build(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var caCommand = new Command("ca", "CA certificate commands");
        caCommand.Subcommands.Add(BuildInfo(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        caCommand.Subcommands.Add(BuildCrl(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        caCommand.Subcommands.Add(BuildApproval(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        caCommand.Subcommands.Add(BuildStrength(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        caCommand.Subcommands.Add(BuildRevokedIssuer(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        return caCommand;
    }

    internal static bool ParseMode(string? text, out bool requireIndependent) =>
        CaApprovalRule.TryParse(text, out requireIndependent);

    internal static string DescribeMode(bool requireIndependent) => CaApprovalRule.ModeName(requireIndependent);

    /// <summary>Only waiving asks first: tightening the rule can never let anyone do more.</summary>
    internal static bool NeedsConfirmation(bool requireIndependent, bool yes) => !requireIndependent && !yes;

    private static Command BuildApproval(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption, Option<string?> tokenOption, Option<string> outputOption)
    {
        var approval = new Command("approval",
            "Who may approve a request for a certificate that can sign other certificates (templates with KeyCertSign, e.g. SubordinateCA).");

        var show = new Command("show", ShowHelp);
        show.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;
            return await CliApi.RunAsync(async () =>
            {
                var settings = await CliApi.CreateClient(session).GetSettingsAsync(ct);
                var mode = DescribeMode(settings.RequireIndependentCaApproval);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(new { caApproval = mode });
                Console.WriteLine(mode);
                return 0;
            }, "reading CA settings needs settings.edit");
        });
        approval.Subcommands.Add(show);

        var modeArg = new Argument<string>("mode") { Description = "independent or waived." };
        var yes = new Option<bool>("--yes") { Description = "Skip the confirmation prompt when setting waived." };
        yes.Aliases.Add("-y");
        var set = new Command("set", SetHelp);
        set.Arguments.Add(modeArg);
        set.Options.Add(yes);
        set.SetAction(async (result, ct) =>
        {
            if (!ParseMode(result.GetValue(modeArg), out var require))
            {
                await Console.Error.WriteLineAsync($"error: unknown mode '{result.GetValue(modeArg)}'; use independent or waived.");
                return 1;
            }
            if (NeedsConfirmation(require, result.GetValue(yes)))
            {
                Console.Write("Waive independent approval? One person will be able to request and approve a CA certificate. [y/N] ");
                if (!string.Equals(Console.ReadLine()?.Trim(), "y", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("Aborted.");
                    return 1;
                }
            }
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;
            return await CliApi.RunAsync(async () =>
            {
                var updated = await CliApi.CreateClient(session).SetCaApprovalRuleAsync(require, ct);
                var mode = DescribeMode(updated.RequireIndependentCaApproval);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(new { caApproval = mode });
                Console.WriteLine($"CA approval is now {mode}");
                return 0;
            }, "changing CA approval needs the admin role");
        });
        approval.Subcommands.Add(set);
        return approval;
    }

    internal static RevokedIssuerMode? ParseRevokedIssuer(string? text) =>
        Enum.TryParse<RevokedIssuerMode>(text, ignoreCase: true, out var mode) && Enum.IsDefined(mode) && !int.TryParse(text, out _)
            ? mode
            : null;

    private static Command BuildRevokedIssuer(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption, Option<string?> tokenOption, Option<string> outputOption)
    {
        var revoked = new Command("revoked-issuer",
            "What happens when the certificate of one of the CA's own issuers (a root or an installed intermediate) is revoked.");

        var show = new Command("show", RevokedIssuerShowHelp);
        show.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;
            return await CliApi.RunAsync(async () =>
            {
                var settings = await CliApi.CreateClient(session).GetSettingsAsync(ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(new { revokedIssuer = settings.RevokedIssuerMode });
                Console.WriteLine(settings.RevokedIssuerMode);
                return 0;
            }, "reading CA settings needs settings.edit");
        });
        revoked.Subcommands.Add(show);

        var modeArg = new Argument<string>("mode") { Description = $"New mode, case-insensitive: {string.Join(", ", Enum.GetNames<RevokedIssuerMode>())}." };
        var set = new Command("set", RevokedIssuerSetHelp);
        set.Arguments.Add(modeArg);
        set.SetAction(async (result, ct) =>
        {
            if (ParseRevokedIssuer(result.GetValue(modeArg)) is not { } mode)
            {
                await Console.Error.WriteLineAsync($"error: unknown mode '{result.GetValue(modeArg)}'; use one of {string.Join(", ", Enum.GetNames<RevokedIssuerMode>())}.");
                return 1;
            }
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;
            return await CliApi.RunAsync(async () =>
            {
                var updated = await CliApi.CreateClient(session).SetRevokedIssuerModeAsync(mode, ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(new { revokedIssuer = updated.RevokedIssuerMode });
                Console.WriteLine($"A revoked CA certificate now triggers {updated.RevokedIssuerMode}");
                return 0;
            }, "changing this setting needs the admin role");
        });
        revoked.Subcommands.Add(set);
        return revoked;
    }

    private const string RevokedIssuerShowHelp =
        "Show what a revoked CA certificate does.\n\n" +
        "Prints HardStop or Retire. Changes nothing.\n" +
        "Needs: settings.edit or the admin role.\n" +
        "Exit codes: 0 shown; 1 not signed in or the call failed (403 when you lack the permission).\n" +
        "Output: --output json prints {\"revokedIssuer\":\"<Mode>\"}.\n" +
        "Example: qca ca revoked-issuer show";

    private const string RevokedIssuerSetHelp =
        "Set what a revoked CA certificate does.\n\n" +
        "When the certificate of a root, or of an intermediate installed under a parent, is revoked, that issuer stops issuing at once, stops being the default and keeps answering CRL and OCSP for what it signed. HardStop (the default) also retires every issuer below it, so with no issuer left that can sign the CA reports itself not initialized, every issuance path answers 409, and onboarding (qca ca generate or import) creates a new root without the force-replace confirmation. Retire only retires the revoked issuer; another active issuer can be made the default. Changes the CA setting for every revocation from then on, and does not touch an issuer that is already retired; when the mode actually changes it writes an audit entry (RevokedIssuerModeChanged) and raises a webhook (setting the current mode again does neither). It does not ask for confirmation.\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 set; 1 unknown mode, not signed in, or the call failed (403 means you are not admin).\n" +
        "Output: --output json prints {\"revokedIssuer\":\"<Mode>\"}.\n" +
        "Example: qca ca revoked-issuer set HardStop";

    internal static IssuerStrengthMode? ParseStrength(string? text) =>
        Enum.TryParse<IssuerStrengthMode>(text, ignoreCase: true, out var mode) && Enum.IsDefined(mode) && !int.TryParse(text, out _)
            ? mode
            : null;

    private static Command BuildStrength(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption, Option<string?> tokenOption, Option<string> outputOption)
    {
        var strength = new Command("strength",
            "What happens when a certificate's post-quantum key claims a higher NIST security level than the CA key that signs it.");

        var show = new Command("show", StrengthShowHelp);
        show.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;
            return await CliApi.RunAsync(async () =>
            {
                var settings = await CliApi.CreateClient(session).GetSettingsAsync(ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(new { issuerStrength = settings.IssuerStrengthMode });
                Console.WriteLine(settings.IssuerStrengthMode);
                return 0;
            }, "reading CA settings needs settings.edit");
        });
        strength.Subcommands.Add(show);

        var modeArg = new Argument<string>("mode") { Description = $"New mode, case-insensitive: {string.Join(", ", Enum.GetNames<IssuerStrengthMode>())}." };
        var set = new Command("set", StrengthSetHelp);
        set.Arguments.Add(modeArg);
        set.SetAction(async (result, ct) =>
        {
            if (ParseStrength(result.GetValue(modeArg)) is not { } mode)
            {
                await Console.Error.WriteLineAsync($"error: unknown mode '{result.GetValue(modeArg)}'; use one of {string.Join(", ", Enum.GetNames<IssuerStrengthMode>())}.");
                return 1;
            }
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;
            return await CliApi.RunAsync(async () =>
            {
                var updated = await CliApi.CreateClient(session).SetIssuerStrengthAsync(mode, ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(new { issuerStrength = updated.IssuerStrengthMode });
                Console.WriteLine($"Issuer strength is now {updated.IssuerStrengthMode}");
                return 0;
            }, "changing issuer strength needs the admin role");
        });
        strength.Subcommands.Add(set);
        return strength;
    }

    private const string StrengthShowHelp =
        "Show the issuer-strength mode.\n\n" +
        "Prints Off, Warn or Enforce. The rule compares the NIST security level of a certificate's post-quantum key (ML-DSA, SLH-DSA, ML-KEM, or the ML-DSA half of a composite or hybrid) with the level of the CA key that signs it. Changes nothing.\n" +
        "Needs: settings.edit or the admin role.\n" +
        "Exit codes: 0 shown; 1 not signed in or the call failed (403 when you lack the permission).\n" +
        "Output: --output json prints {\"issuerStrength\":\"<Mode>\"}.\n" +
        "Example: qca ca strength show";

    private const string StrengthSetHelp =
        "Set the issuer-strength mode.\n\n" +
        "Off skips the comparison. Warn (the default) allows a certificate whose key claims a higher level than its issuer's and attaches a warning. Enforce refuses it as an issuance policy violation, and refuses creating an intermediate CA whose key claims more than its parent's. A classical (RSA or ECDSA) issuer is exempt, so a P-384 root can still sign an ML-DSA-87 CA. Changes the CA setting for new, renewed and approved requests and for requests already queued; when the mode actually changes it writes an audit entry (IssuerStrengthChanged) and raises a webhook (setting the current mode again does neither). It does not ask for confirmation.\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 set; 1 unknown mode, not signed in, or the call failed (403 means you are not admin).\n" +
        "Output: --output json prints {\"issuerStrength\":\"<Mode>\"}.\n" +
        "Example: qca ca strength set Enforce";

    private const string ShowHelp =
        "Show whether a CA-certificate request must be approved by someone other than its requester.\n\n" +
        "Prints 'independent' (approver must differ from requester) or 'waived' (requester may approve their own). Changes nothing.\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 printed; 1 failed (not signed in, 403, network).\n" +
        "Output: --output json prints {\"caApproval\":\"independent\"|\"waived\"}.\n" +
        "Example: qca ca approval show";

    private const string SetHelp =
        "Set whether a CA-certificate request must be approved by someone other than its requester.\n\n" +
        "independent (the default) refuses approval by the requester, admin included. waived lets one person request and approve a CA certificate; every such approval is audited as waived. " +
        "Changes the CA setting, writes an audit entry (CaApprovalRuleChanged) and raises a webhook. Setting waived asks for confirmation unless --yes is given; independent never asks.\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 set; 1 unknown mode, declined, or failed (403 means you are not admin).\n" +
        "Output: --output json prints {\"caApproval\":\"independent\"|\"waived\"}.\n" +
        "Example: qca ca approval set waived --yes";

    private const string ResetBaseHelp =
        "Publish a fresh full CRL now and make it the base for delta CRLs.\n\n" +
        "Instead of waiting for the next /crl fetch, builds and caches a new full CRL for the issuer served at /crl (the legacy issuer while it is Active or Retired, else the default), claims the next CRL number, records it as the delta base and drops the cached delta. Resets the delta CRL base and writes an audit entry (CrlBaseReset). It always acts on that issuer; the command has no option to pick another one.\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 reset; 1 not signed in or the call failed (403 means you lack settings.edit; 503 means no CA certificate is configured yet; 409 means the issuer cannot sign a CRL).\n" +
        "Output: --output json prints the contract (crlNumber, thisUpdateUtc); otherwise the new CRL number and its This Update time.\n" +
        "Example: qca ca crl reset-base";

    private const string InfoHelp =
        "Show the CA certificate's subject, algorithm and validity.\n\n" +
        "Reads the default issuer's certificate; it changes nothing. If the CA has no certificate yet it says so and still exits 0. An ECDSA root with explicit curve parameters adds a warning line.\n" +
        "Needs: any signed-in caller (no particular permission).\n" +
        "Exit codes: 0 shown (including 'CA is not initialized'); 1 not signed in or the call failed.\n" +
        "Output: --output json prints the CA status contract (including isInitialized); otherwise a table of subject DN, algorithm, name parts and validity.\n" +
        "Example: qca ca info --output json";

    private static Command BuildCrl(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var crlCommand = new Command("crl", "CRL / delta CRL commands");
        crlCommand.Subcommands.Add(BuildResetBase(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        return crlCommand;
    }

    private static Command BuildResetBase(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var cmd = new Command("reset-base", ResetBaseHelp);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            return await CliApi.RunAsync(async () =>
            {
                var reset = await CliApi.CreateClient(session).ResetCrlBaseAsync(ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(reset);

                PrintRow("New CRL Number", reset.CrlNumber.ToString());
                PrintRow("This Update",    reset.ThisUpdateUtc.ToString("u"));
                return 0;
            });
        });

        return cmd;
    }

    private static Command BuildInfo(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var cmd = new Command("info", InfoHelp);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            return await CliApi.RunAsync(async () =>
            {
                var status = await CliApi.CreateClient(session).GetCaStatusAsync(ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(status);

                if (!status.IsInitialized)
                {
                    Console.WriteLine("CA is not initialized. Complete onboarding at the web UI.");
                    return 0;
                }

                PrintRow("Subject DN",   status.SubjectDn);
                PrintRow("Algorithm",    status.Algorithm);
                PrintRow("Common Name",  status.CaCommonName);
                PrintRow("Organization", status.OrganizationName);
                PrintRow("Org Unit",     status.OrganizationalUnit);
                PrintRow("Country",      status.Country);
                PrintRow("State",        status.State);
                PrintRow("Locality",     status.Locality);
                PrintRow("Valid From",   status.ValidFrom?.ToString("u"));
                PrintRow("Valid To",     status.ValidTo?.ToString("u"));
                if (status.ExplicitCurveParameters)
                {
                    Console.WriteLine();
                    Console.WriteLine($"Warning: {Qertum.Services.CaStatusResponse.ExplicitCurveParametersWarning}");
                }
                return 0;
            });
        });

        return cmd;
    }

    private static void PrintRow(string label, string? value) =>
        Console.WriteLine($"{label,-18} {value ?? "-"}");
}
