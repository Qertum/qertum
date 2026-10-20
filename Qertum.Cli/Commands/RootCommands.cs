using System.CommandLine;
using System.Text.Json;
using Qertum.Cli.Root;
using Qertum.Services;
using Qertum.Services.Issuers;

namespace Qertum.Cli.Commands;

/// <summary>
/// <c>qca root init|sign|crl</c>: an offline root CA in a directory. No server, no network, no
/// authentication. The passphrase is only ever prompted for — never an argument or environment
/// variable, which would land in shell history or process listings.
/// </summary>
internal static class RootCommands
{
    public static Command Build(IPassphrasePrompt? prompt = null)
    {
        prompt ??= new ConsolePassphrasePrompt();
        var root = new Command("root", "Offline root CA: create it, sign intermediate request files, sign its CRL. Runs without a server.");
        root.Subcommands.Add(BuildInit(prompt));
        root.Subcommands.Add(BuildSign(prompt));
        root.Subcommands.Add(BuildCrl(prompt));
        return root;
    }

    private const string InitHelp =
        "Create a new offline root CA in a directory, with its key encrypted by a passphrase.\n\n" +
        "Creates root.key (encrypted PKCS#8), root.pem (the self-signed root) and state.json in --dir, which must not exist or must be empty (an existing root is never overwritten). Generates the key locally; nothing is sent anywhere. " +
        "The passphrase is prompted for twice (hidden, written to stderr), never taken as an argument or environment variable; an empty or mismatched passphrase is refused.\n" +
        "Needs: nothing (offline, no server).\n" +
        "Exit codes: 0 created; 1 the algorithm cannot be a root key, the passphrase was empty or mismatched, or --dir is not empty. An unwritable --dir is not handled and crashes with an unhandled error.\n" +
        "Output: text only (subject, algorithm, validity, file paths); --output json makes no difference.\n" +
        "Example: qca root init --dir ./offline-root --cn \"Example Root CA\" --algorithm ECDSA-P384";

    private const string SignHelp =
        "Sign an intermediate's request file with the offline root.\n\n" +
        "Reads the request file, checks its CSR signature, prints the subject, algorithm, validity and constraints it would sign and asks to confirm (unless --yes). The root passphrase is then prompted for, never an argument. " +
        "Signs a CA certificate with the root key, writes <name>.pem and chain.pem into --dir and records the serial in state.json; the validity may not outlast the root. The CLI prints the 'qca issuers install' command to run next.\n" +
        "Needs: nothing (offline, no server).\n" +
        "Exit codes: 0 signed; 1 you declined, the request file or a root file is missing or empty, the request's CSR signature fails, the passphrase is wrong, or the requested validity outlasts the root.\n" +
        "Output: text only (the request summary, the certificate and chain paths); --output json makes no difference.\n" +
        "Example: qca root sign --dir ./offline-root --request issuing-ca.request.json";

    private const string CrlHelp =
        "Sign the offline root's CRL, adding any revocations given now.\n\n" +
        "Signs a new CRL (root.crl in --dir) listing every serial revoked so far plus those given with --revoke, and increases the CRL number kept in state.json. Records the new revocations in state.json. " +
        "The root passphrase is prompted for, never an argument. Upload the file with 'qca issuers upload-crl'; run this again before the CRL's validity ends, even with nothing to revoke.\n" +
        "Needs: nothing (offline, no server).\n" +
        "Exit codes: 0 signed; 1 a root file is missing or empty or the passphrase is wrong.\n" +
        "Output: text only (the CRL path and the next command); --output json makes no difference.\n" +
        "Example: qca root crl --dir ./offline-root --revoke 1A2B3C --reason keyCompromise";

    private static Option<string> Required(string name, string description) =>
        new(name) { Description = description, Required = true };

    private static Command BuildInit(IPassphrasePrompt prompt)
    {
        var dir = Required("--dir", "Directory for the new root (required): must not exist or must be empty; root.key, root.pem and state.json are created in it.");
        var cn = Required("--cn", "Root subject common name (required).");
        var o = new Option<string?>("--o") { Description = "Subject organization (optional)." };
        var ou = new Option<string?>("--ou") { Description = "Subject organizational unit (optional)." };
        var c = new Option<string?>("--c") { Description = "Subject country, ISO 3166-1 alpha-2 code (optional)." };
        var st = new Option<string?>("--st") { Description = "Subject state (optional)." };
        var l = new Option<string?>("--l") { Description = "Subject locality (optional)." };
        var algorithm = Required("--algorithm", "Root key algorithm (required), e.g. ECDSA-P384, ML-DSA-87, RSA, or a composite name. Any signing algorithm except hybrid, ML-KEM and signing + encryption pairs; an unsuitable value is refused with the list of eligible ones.");
        var validity = new Option<int>("--validity-days") { Description = "Root validity in days (default 7300).", DefaultValueFactory = _ => 7300 };

        var cmd = new Command("init", InitHelp);
        foreach (var option in new Option[] { dir, cn, o, ou, c, st, l, algorithm, validity }) cmd.Options.Add(option);

        cmd.SetAction(result => Run(() =>
        {
            var parsed = CertificateKeyAlgorithmExtensions.Parse(result.GetValue(algorithm));
            if (parsed is not { } keyAlgorithm || !keyAlgorithm.CanSign() || keyAlgorithm.GetFamily() == AlgorithmFamily.Hybrid)
            {
                var eligible = Enum.GetValues<CertificateKeyAlgorithm>()
                    .Where(a => a.CanSign() && a.GetFamily() != AlgorithmFamily.Hybrid)
                    .Select(a => a.ToCanonicalString());
                Console.Error.WriteLine($"'{result.GetValue(algorithm)}' cannot be a root key. Choose one of: {string.Join(", ", eligible)}");
                return 1;
            }

            var passphrase = prompt.Read("New root passphrase: ");
            if (passphrase.Length == 0) { Console.Error.WriteLine("The passphrase must not be empty."); return 1; }
            if (prompt.Read("Repeat passphrase: ") != passphrase) { Console.Error.WriteLine("Passphrases do not match."); return 1; }

            var directory = result.GetValue(dir)!;
            var subject = CaCertificateBuilder.SubjectName(result.GetValue(cn)!, result.GetValue(o), result.GetValue(ou),
                result.GetValue(c), result.GetValue(st), result.GetValue(l));
            new OfflineRoot(directory, TimeProvider.System).Init(subject, keyAlgorithm, result.GetValue(validity), passphrase);

            Console.WriteLine($"Root created: {subject} ({keyAlgorithm.ToCanonicalString()}, {result.GetValue(validity)} days)");
            Console.WriteLine($"  key:         {Path.Combine(directory, OfflineRoot.KeyFile)} (encrypted)");
            Console.WriteLine($"  certificate: {Path.Combine(directory, OfflineRoot.CertificateFile)}");
            return 0;
        }));
        return cmd;
    }

    private static Command BuildSign(IPassphrasePrompt prompt)
    {
        var dir = Required("--dir", "Offline root directory created by 'qca root init' (required).");
        var request = Required("--request", "Path to the request file (required) written by 'qca issuers create-intermediate' or fetched with 'qca issuers request'.");
        var yes = new Option<bool>("--yes") { Description = "Sign without asking for confirmation (default: show the request and ask; anything but y exits 1)." };

        var cmd = new Command("sign", SignHelp);
        foreach (var option in new Option[] { dir, request, yes }) cmd.Options.Add(option);

        cmd.SetAction(result => Run(() =>
        {
            var file = JsonSerializer.Deserialize<IntermediateRequestFile>(File.ReadAllText(result.GetValue(request)!),
                           new JsonSerializerOptions(JsonSerializerDefaults.Web))
                       ?? throw new InvalidOperationException("The request file is empty.");
            var root = new OfflineRoot(result.GetValue(dir)!, TimeProvider.System);
            var preview = root.Preview(file);
            Console.WriteLine($"Subject:     {preview.SubjectDn}");
            Console.WriteLine($"Algorithm:   {preview.Algorithm}");
            Console.WriteLine($"Validity:    {preview.ValidityDays} days (until {preview.NotAfterUtc:yyyy-MM-dd})");
            Console.WriteLine($"Constraints: {preview.Constraints}");
            if (!result.GetValue(yes))
            {
                Console.Write("Sign this intermediate? [y/N] ");
                if (!string.Equals(Console.ReadLine()?.Trim(), "y", StringComparison.OrdinalIgnoreCase)) return 1;
            }

            var (certificatePath, chainPath) = root.Sign(file, prompt.Read("Root passphrase: "));
            Console.WriteLine($"Certificate: {certificatePath}");
            Console.WriteLine($"Chain:       {chainPath}");
            Console.WriteLine($"Next: qca issuers install {file.IssuerId} --cert {certificatePath} --chain {chainPath}");
            return 0;
        }));
        return cmd;
    }

    private static Command BuildCrl(IPassphrasePrompt prompt)
    {
        var dir = Required("--dir", "Offline root directory created by 'qca root init' (required).");
        var revoke = new Option<string[]>("--revoke") { Description = "Serial number (hex) of an intermediate to revoke; repeatable. Default: none, which re-signs the CRL with the revocations recorded so far.", AllowMultipleArgumentsPerToken = false };
        var reason = new Option<string[]>("--reason") { Description = "Reason for the --revoke at the same position; repeatable. One of keyCompromise, caCompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, removeFromCrl, privilegeWithdrawn, aaCompromise; anything else or omitted is recorded as unspecified." };
        var validity = new Option<int>("--validity-days") { Description = "CRL validity in days (default 365).", DefaultValueFactory = _ => 365 };

        var cmd = new Command("crl", CrlHelp);
        foreach (var option in new Option[] { dir, revoke, reason, validity }) cmd.Options.Add(option);

        cmd.SetAction(result => Run(() =>
        {
            var serials = result.GetValue(revoke) ?? [];
            var reasons = result.GetValue(reason) ?? [];
            var entries = serials.Select((s, i) => (s, i < reasons.Length ? reasons[i] : (string?)null)).ToList();
            var path = new OfflineRoot(result.GetValue(dir)!, TimeProvider.System)
                .Crl(entries, result.GetValue(validity), prompt.Read("Root passphrase: "));
            Console.WriteLine($"CRL: {path}");
            Console.WriteLine("Next: qca issuers upload-crl <root issuer id> " + path);
            return 0;
        }));
        return cmd;
    }

    private static int Run(Func<int> action)
    {
        try
        {
            return action();
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or IOException or JsonException or NotSupportedException)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }
}
