using System.CommandLine;
using Qertum.Cli.Api;
using Qertum.Cli.Auth;
using Qertum.Cli.Doctor;
using Qertum.Cli.Doctor.Checks;

namespace Qertum.Cli.Commands;

/// <summary><c>qca doctor</c>: read-only diagnostics run from this machine.</summary>
internal static class DoctorCommands
{
    private static readonly Option<int> TimeoutOption = new("--timeout")
    {
        Description = "Seconds to wait for each network probe, 1 to 120 (default 10).",
        DefaultValueFactory = _ => 10
    };

    private const string Help =
        "Check, from this machine, whether the CA can be reached, trusted and used.\n\n" +
        "Runs read-only checks one after another: API and identity-provider reachability, your session, issuers, the trust anchors (including whether this machine's trust store holds the root), ACME and EST reachability, CRL freshness and the server's own attention report. Each check says what it verified and what it did not. It never writes to the server, the trust store or the saved session, and never refreshes a token; without a login only the checks that need none run and the rest are skipped with a reason.\n" +
        "Needs: nothing for the api, identity, trust (roots) and revocation checks; a saved session or --token for the rest (certificates.view for the issuer list, certificates.create for the enrollment options, settings.edit for the CRL setting).\n" +
        "Exit codes: 0 no warnings or failures; 2 warnings only; 1 at least one failure, or --timeout out of range. Skipped checks never change the code but are counted in the summary.\n" +
        "Output: --output json prints checks (id, status, summary, verified, notVerified, findings, hint, reason), summary and exitCode.\n" +
        "Example: qca doctor --api-url https://ca.example.org --identity-url https://id.example.org";

    public static Command Build(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption, Option<string?> tokenOption, Option<string> outputOption) =>
        Build(apiUrlOption, identityUrlOption, tokenOption, outputOption,
            () => new HttpClientHandler { AllowAutoRedirect = false }, new OsRootStore(), TimeProvider.System, TokenCache.Load);

    internal static Command Build(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption, Option<string?> tokenOption, Option<string> outputOption,
        Func<HttpMessageHandler> handlerFactory, IRootStore rootStore, TimeProvider clock, Func<CachedSession?> loadSession)
    {
        var command = new Command("doctor", Help);
        command.Options.Add(TimeoutOption);
        command.SetAction(async (result, ct) =>
        {
            var seconds = result.GetValue(TimeoutOption);
            if (seconds is < 1 or > 120)
            {
                await Console.Error.WriteLineAsync("error: --timeout must be between 1 and 120 seconds.");
                return 1;
            }

            var inputs = new DoctorInputs(
                result.GetValue(apiUrlOption) ?? Environment.GetEnvironmentVariable("QERTUM_API_URL"),
                result.GetValue(identityUrlOption) ?? Environment.GetEnvironmentVariable("QERTUM_IDENTITY_URL"),
                result.GetValue(tokenOption) ?? Environment.GetEnvironmentVariable("QERTUM_TOKEN"));

            using var handler = handlerFactory();
            var context = DoctorContextFactory.Create(inputs, loadSession, handler, clock, rootStore, TimeSpan.FromSeconds(seconds));
            return await RunAsync(context, result.GetValue(outputOption) == "json", Console.Out, ct);
        });
        return command;
    }

    /// <summary>The eight checks, in the order later ones rely on.</summary>
    internal static IReadOnlyList<IDoctorCheck> AllChecks() =>
    [
        new ApiCheck(), new IdentityCheck(), new SessionCheck(), new IssuersCheck(),
        new TrustCheck(), new EnrollmentCheck(), new RevocationCheck(), new ServerReportsCheck()
    ];

    /// <summary>Runs every check, writes the table or JSON, and returns the exit code.</summary>
    internal static async Task<int> RunAsync(DoctorContext context, bool json, TextWriter output, CancellationToken ct)
    {
        var report = await DoctorRunner.RunAsync(AllChecks(), context, ct);
        if (json)
            await output.WriteLineAsync(System.Text.Json.JsonSerializer.Serialize(DoctorRenderer.Json(report),
                new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web) { WriteIndented = true }));
        else
            await output.WriteAsync(DoctorRenderer.Table(report));
        return report.ExitCode;
    }
}
