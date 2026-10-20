using System.CommandLine;
using System.Text.Json;
using Qertum.Cli.Api;
using Qertum.Cli.Auth;
using Qertum.Services;

namespace Qertum.Cli.Commands;

/// <summary><c>qca issuers</c>: list and inspect issuers, run the intermediate ceremony, publish an offline root's CRL.</summary>
internal static class IssuerCommands
{
    private static readonly JsonSerializerOptions FileJson = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    // Shared by the parser and BuildCreateRequest so both see the same option instances.
    private static readonly Option<string> NameOption = new("--name") { Description = "Unique issuer name (required, at most 200 characters).", Required = true };
    private static readonly Option<string> CnOption = new("--cn") { Description = "Subject common name (required, at most 200 characters).", Required = true };
    private static readonly Option<string?> OOption = new("--o") { Description = "Subject organization." };
    private static readonly Option<string?> OuOption = new("--ou") { Description = "Subject organizational unit." };
    private static readonly Option<string?> COption = new("--c") { Description = "Subject country, ISO 3166-1 alpha-2 code (for example SE)." };
    private static readonly Option<string?> StOption = new("--st") { Description = "Subject state." };
    private static readonly Option<string?> LOption = new("--l") { Description = "Subject locality." };
    private static readonly Option<string?> AlgorithmOption = new("--algorithm") { Description = "CA key algorithm, e.g. ECDSA-P384, ECDSA-P256, RSA, ML-DSA-65. Default ECDSA-P384. Must be a signing algorithm that is not hybrid or ML-KEM, and the CA's PQC stage must allow it." };
    private static readonly Option<int> ValidityOption = new("--validity-days") { Description = "Validity in days, 1 to 36500 (default 1825).", DefaultValueFactory = _ => 1825 };
    private static readonly Option<string> PathLengthOption = new("--path-length") { Description = "pathLenConstraint: a number from 0 to 10, or 'none' for no limit (default 0, so the intermediate can only issue leaf certificates).", DefaultValueFactory = _ => "0" };
    private static readonly Option<string[]> PermitDnsOption = new("--permit-dns") { Description = "Name constraint: permitted DNS domain, no wildcards; repeatable (at most 50). Default none (unconstrained)." };
    private static readonly Option<string[]> ExcludeDnsOption = new("--exclude-dns") { Description = "Name constraint: excluded DNS domain, no wildcards; repeatable (at most 50). Default none." };
    private static readonly Option<string[]> PermitIpOption = new("--permit-ip") { Description = "Name constraint: permitted IP range in CIDR form such as 10.0.0.0/8; repeatable (at most 50). Default none (unconstrained)." };
    private static readonly Option<string[]> ExcludeIpOption = new("--exclude-ip") { Description = "Name constraint: excluded IP range in CIDR form; repeatable (at most 50). Default none." };
    private static readonly Option<Guid?> ParentOption = new("--parent") { Description = "Parent issuer id (a GUID from 'qca issuers list'). An online Active parent signs the intermediate now; an offline parent, or omitting --parent, produces a request file for 'qca root sign'." };
    private static readonly Option<string?> RequestFileOption = new("--request-file", "-f") { Description = "Where to write the request file when one is produced (default <name>.request.json in the current directory, with the name made file-safe)." };

    private const string ListHelp =
        "List every issuer, roots first.\n\n" +
        "Reads the issuer registry; it changes nothing. Shows name, kind, key custody, status, a * on the default issuer, validity end and id.\n" +
        "Needs: certificates.view.\n" +
        "Exit codes: 0 listed; 1 not signed in or the call failed.\n" +
        "Output: --output json prints the array of issuer contracts.\n" +
        "Example: qca issuers list --output json";

    private const string ShowHelp =
        "Show one issuer's details.\n\n" +
        "Reads the issuer; it changes nothing. Prints id, name, kind, custody, status, parent, subject, algorithm, validity, path length, name constraints and, for an offline issuer, its uploaded CRL.\n" +
        "Needs: certificates.view.\n" +
        "Exit codes: 0 shown; 1 not signed in, no such issuer, or the call failed.\n" +
        "Output: --output json prints the issuer contract.\n" +
        "Example: qca issuers show 3f2c9a1e-0000-0000-0000-000000000000";

    private const string CreateIntermediateHelp =
        "Create an intermediate issuer: signed now by an online parent, otherwise as a request file for an offline root.\n\n" +
        "Creates the issuer and generates its key on the server. With --parent set to an online Active issuer the certificate is issued at once and the issuer is Active. With an offline parent, or no --parent, it stays PendingCertificate and the command writes a request file (see --request-file) to take to 'qca root sign', then 'qca issuers install'. " +
        "Audited as IssuerCreated.\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 created; 1 not signed in, the server refused, or the call failed (403 means you are not admin; 409 duplicate name or a parent that cannot sign; 400 or 422 invalid options or a refused algorithm).\n" +
        "Output: --output json prints the contract (issuer and requestFile) only when the intermediate was signed immediately; when a request file is produced the issuer table is printed and the file written regardless of --output.\n" +
        "Example: qca issuers create-intermediate --name \"Issuing CA 1\" --cn \"Example Issuing CA 1\" --permit-dns example.com";

    private const string RequestHelp =
        "Fetch the request file of a pending intermediate.\n\n" +
        "Reads the stored request file (CSR plus the requested constraints) so you can take it to the offline root; it changes nothing on the server. Use it if the file written by create-intermediate was lost.\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 fetched; 1 not signed in or the call failed (404 unknown id; 409 the issuer has no request file).\n" +
        "Output: the request file as indented JSON, to stdout or to --file; --output json makes no difference.\n" +
        "Example: qca issuers request 3f2c9a1e-0000-0000-0000-000000000000 --file issuing-ca.request.json";

    private const string InstallHelp =
        "Install the signed certificate and chain on a pending intermediate and activate it.\n\n" +
        "Reads the two PEM files and sends them. The server checks that the certificate matches the pending key, is a CA with keyCertSign, chains to a self-signed root, is nested in its parent's validity and carries constraints at least as strict as requested. " +
        "Installs the certificate and changes the issuer from PendingCertificate to Active; audited as IssuerCertificateInstalled.\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 installed; 1 not signed in, the server refused, or the call failed (404 unknown id; 409 not pending or the certificate does not qualify).\n" +
        "Output: --output json prints the issuer contract; otherwise the issuer table.\n" +
        "Example: qca issuers install 3f2c9a1e-0000-0000-0000-000000000000 --cert issuing-ca.pem --chain issuing-ca.chain.pem";

    private const string UploadCrlHelp =
        "Upload the CRL of an offline issuer so the CA serves it.\n\n" +
        "Sends the CRL file; the server checks the issuer name and signature, an increasing CRL number and a future nextUpdate. Uploads and publishes the CRL at /crl/{issuerId}; intermediates it lists as revoked are retired. Only for an Active or Retired offline issuer; online issuers sign their own.\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 published; 1 not signed in, the server refused, or the call failed (409 wrong issuer kind or status; 413 over 1 MiB).\n" +
        "Output: --output json prints the issuer contract; otherwise one line with the CRL number and next update.\n" +
        "Example: qca issuers upload-crl 3f2c9a1e-0000-0000-0000-000000000000 root.crl";

    private const string DeleteHelp =
        "Abandon a pending intermediate and delete its key.\n\n" +
        "Deletes the issuer row and its generated key. Only an issuer still waiting for its certificate (PendingCertificate) can be deleted; an issued one is retired and archived instead. Asks for confirmation unless --yes is given. Audited as IssuerDeleted.\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 deleted; 1 not signed in, you declined, the issuer is not pending (409), or the call failed (403 means you are not admin).\n" +
        "Output: the text 'Deleted.'; --output json makes no difference.\n" +
        "Example: qca issuers delete 3f2c9a1e-0000-0000-0000-000000000000 --yes";

    private const string MakeDefaultHelp =
        "Make an Active, online issuer the default for new certificates.\n\n" +
        "Sets the default issuer: certificates from templates not pinned to an issuer are signed by it from now on, and the previous default stops being the default. Existing certificates are untouched. Asks for confirmation unless --yes is given. Audited as IssuerMadeDefault.\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 changed; 1 not signed in, you declined or the server refused (409 not Active, offline or without its key; 403 not admin).\n" +
        "Output: --output json prints the issuer contract; otherwise the issuer table.\n" +
        "Example: qca issuers make-default 3f2c9a1e-0000-0000-0000-000000000000 --yes";

    private const string RetireHelp =
        "Stop an issuer from signing new certificates.\n\n" +
        "Retires an Active issuer: it no longer issues, but keeps answering CRL and OCSP for what it signed. The default issuer cannot be retired; make another issuer default first. Asks for confirmation unless --yes is given. Audited as IssuerRetired.\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 retired; 1 not signed in, you declined or the server refused (409 it is the default or not Active; 403 not admin).\n" +
        "Output: --output json prints the issuer contract; otherwise the issuer table.\n" +
        "Example: qca issuers retire 3f2c9a1e-0000-0000-0000-000000000000 --yes";

    private const string ArchiveHelp =
        "Archive a retired issuer once nothing it signed is still valid, and delete its key.\n\n" +
        "Archives a Retired issuer whose issued certificates have all expired (a revoked but unexpired certificate still counts). Deletes the issuer's private key permanently but keeps its row. Asks for confirmation unless --yes is given. Audited as IssuerArchived.\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 archived; 1 not signed in, you declined or the server refused (409 not Retired or certificates still unexpired; 403 not admin).\n" +
        "Output: --output json prints the issuer contract; otherwise the issuer table.\n" +
        "Example: qca issuers archive 3f2c9a1e-0000-0000-0000-000000000000 --yes";

    private const string TrustBundleHelp =
        "Download the root certificates of every Active or Retired issuer as one bundle.\n\n" +
        "Reads the public trust anchors, de-duplicated; it changes nothing. The server endpoint is anonymous, but the CLI still needs a saved session or --token like every other command.\n" +
        "Needs: nothing beyond a signed-in CLI (the endpoint itself requires no permission).\n" +
        "Exit codes: 0 written or printed; 1 not signed in, the format is not exactly pem and no --file was given, or the call failed (503 means no trust anchor is configured yet).\n" +
        "Output: the bundle itself (PEM text to stdout, or a file with --file); --output json makes no difference.\n" +
        "Example: qca issuers trust-bundle --format p7b --file trust.p7b";

    private const string KeyExportWarning =
        "WARNING: this is not a safe way to manage a CA private key. Whoever holds the file can sign certificates that every client " +
        "trusting this CA will accept. Keep a CA key in an HSM or an offline ceremony; export it only for a backup you will store " +
        "offline or a migration you control, then delete every other copy. The export is audited.";

    private const string ExportKeyHelp =
        "Download an online issuer's private key as an unencrypted PEM file. This is not a safe way to manage a CA private key.\n\n" +
        "Creates a local file (owner-only permissions where the OS supports them) holding the issuer's unprotected signing key. Changes server records only by auditing: every export is audited as IssuerKeyDownloaded and announced to KeyAccess webhooks. Only an Active or Retired issuer with Online custody has a key on the server. Prints a warning and asks for confirmation unless --yes is given.\n" +
        "Needs: the admin role (not a grantable permission); a step-up token when step-up is on; an approved request (operation issuer-key-export) when two-person approval is on.\n" +
        "Exit codes: 0 written; 1 not signed in, you declined, no key on this server (404), access refused, or the call failed (403 means you are not admin).\n" +
        "Output: 'written <path>'; --output json makes no difference.\n" +
        "Example: qca issuers export-key 3f2c9a1e-0000-0000-0000-000000000000 --file issuing-ca.key";

    private const string ExportPfxHelp =
        "Download an online issuer's certificate and private key as a password-protected PKCS#12 file. This is not a safe way to manage a CA private key.\n\n" +
        "Creates a local file (owner-only permissions where the OS supports them). Changes server records only by auditing: every export is audited as IssuerPfxExported and announced to KeyAccess webhooks. Only an Active or Retired issuer with Online custody has a key on the server. Prints a warning and asks for confirmation unless --yes is given.\n" +
        "Needs: the admin role (not a grantable permission); a step-up token when step-up is on; an approved request (operation issuer-pfx-export) when two-person approval is on.\n" +
        "Exit codes: 0 written; 1 not signed in, you declined, an empty password, no key on this server (404), access refused, or the call failed (403 means you are not admin).\n" +
        "Output: 'written <path>'; --output json makes no difference.\n" +
        "Example: qca issuers export-pfx 3f2c9a1e-0000-0000-0000-000000000000 --file issuing-ca.pfx --pfx-password \"correct horse\"";

    public static Command Build(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var cmd = new Command("issuers", "Certificate authorities: list, ceremonies, rollover, trust bundle");
        Command Sub(string name, string description, Func<ParseResult, CertificateRequestsApiClient, CancellationToken, Task<int>> run,
            params Symbol[] symbols)
        {
            var sub = new Command(name, description);
            foreach (var symbol in symbols)
            {
                if (symbol is Option option) sub.Options.Add(option);
                else if (symbol is Argument argument) sub.Arguments.Add(argument);
            }
            sub.SetAction(async (result, ct) =>
            {
                var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
                if (session is null) return 1;
                return await CliApi.RunAsync(() => run(result, CliApi.CreateClient(session), ct),
                    "Issuer changes need the admin role.");
            });
            cmd.Subcommands.Add(sub);
            return sub;
        }

        bool Json(ParseResult r) => r.GetValue(outputOption) == "json";

        Sub("list", ListHelp, async (r, api, ct) =>
        {
            var issuers = await api.GetIssuersAsync(ct);
            if (Json(r)) return CliApi.PrintJson(issuers);
            Console.WriteLine($"{"Name",-28}  {"Kind",-12}  {"Custody",-8}  {"Status",-18}  {"Def",-3}  {"Valid To",-10}  Id");
            foreach (var i in issuers)
                Console.WriteLine($"{CliApi.Trunc(i.Name, 28),-28}  {i.Kind,-12}  {i.KeyCustody,-8}  {i.Status,-18}  {(i.IsDefault ? "*" : ""),-3}  {i.ValidTo?.ToString("yyyy-MM-dd") ?? "",-10}  {i.Id}");
            return 0;
        });

        var showId = new Argument<Guid>("id") { Description = "Issuer id (GUID, from 'qca issuers list')." };
        Sub("show", ShowHelp, async (r, api, ct) =>
        {
            var issuer = await api.GetIssuerAsync(new IssuerId(r.GetValue(showId)), ct);
            if (issuer is null) { Console.Error.WriteLine("No such issuer."); return 1; }
            if (Json(r)) return CliApi.PrintJson(issuer);
            PrintIssuer(issuer);
            return 0;
        }, showId);

        Sub("create-intermediate", CreateIntermediateHelp, async (r, api, ct) =>
        {
            var request = BuildCreateRequest(r);
            var created = await api.CreateIntermediateAsync(request, ct);
            if (Json(r) && created.RequestFile is null) return CliApi.PrintJson(created);
            PrintIssuer(created.Issuer);
            if (created.RequestFile is { } file)
            {
                var path = r.GetValue(RequestFileOption) ?? $"{SafeFileName(created.Issuer.Name)}.request.json";
                await File.WriteAllTextAsync(path, JsonSerializer.Serialize(file, FileJson), ct);
                Console.WriteLine($"Request file: {path}");
                Console.WriteLine($"Next: qca root sign --dir <root-dir> --request {path}");
                Console.WriteLine($"Then: qca issuers install {created.Issuer.Id} --cert <cert> --chain <chain>");
            }
            return 0;
        }, NameOption, CnOption, OOption, OuOption, COption, StOption, LOption, AlgorithmOption, ValidityOption, PathLengthOption,
            PermitDnsOption, ExcludeDnsOption, PermitIpOption, ExcludeIpOption, ParentOption, RequestFileOption);

        var requestId = new Argument<Guid>("id") { Description = "Id of a pending intermediate issuer (GUID, from 'qca issuers list')." };
        var requestOut = new Option<string?>("--file", "-f") { Description = "Where to write the request file (default: print it to stdout)." };
        Sub("request", RequestHelp, async (r, api, ct) =>
        {
            var file = await api.GetIntermediateRequestFileAsync(new IssuerId(r.GetValue(requestId)), ct);
            var json = JsonSerializer.Serialize(file, FileJson);
            if (r.GetValue(requestOut) is { } path) await File.WriteAllTextAsync(path, json, ct);
            else Console.WriteLine(json);
            return 0;
        }, requestId, requestOut);

        var installId = new Argument<Guid>("id") { Description = "Id of the pending intermediate issuer to install the certificate on (GUID)." };
        var certOption = new Option<string>("--cert") { Description = "Path to the signed intermediate certificate, PEM (required; the 'certificate' file written by 'qca root sign').", Required = true };
        var chainOption = new Option<string>("--chain") { Description = "Path to the chain, PEM: the root and any CA between it and the intermediate (required; the 'chain' file written by 'qca root sign').", Required = true };
        Sub("install", InstallHelp, async (r, api, ct) =>
        {
            var installed = await api.InstallIssuerCertificateAsync(new IssuerId(r.GetValue(installId)),
                new InstallIssuerCertificateRequest(await File.ReadAllTextAsync(r.GetValue(certOption)!, ct),
                    await File.ReadAllTextAsync(r.GetValue(chainOption)!, ct)), ct);
            if (Json(r)) return CliApi.PrintJson(installed);
            PrintIssuer(installed);
            return 0;
        }, installId, certOption, chainOption);

        var crlId = new Argument<Guid>("id") { Description = "Id of an Active or Retired offline issuer (GUID)." };
        var crlFile = new Argument<string>("file") { Description = "Path to the CRL file, DER or PEM, as written by 'qca root crl' (at most 1 MiB)." };
        Sub("upload-crl", UploadCrlHelp, async (r, api, ct) =>
        {
            var issuer = await api.UploadIssuerCrlAsync(new IssuerId(r.GetValue(crlId)), await File.ReadAllBytesAsync(r.GetValue(crlFile)!, ct), ct);
            if (Json(r)) return CliApi.PrintJson(issuer);
            Console.WriteLine($"CRL {issuer.UploadedCrlNumber} published for {issuer.Name}; next update {issuer.UploadedCrlNextUpdateUtc:u}.");
            return 0;
        }, crlId, crlFile);

        var deleteId = new Argument<Guid>("id") { Description = "Id of a pending intermediate issuer (GUID)." };
        var deleteYes = new Option<bool>("--yes") { Description = "Skip the confirmation prompt (default: ask; answering anything but y exits 1)." };
        Sub("delete", DeleteHelp, async (r, api, ct) =>
        {
            if (!r.GetValue(deleteYes) && !Confirm($"Delete pending issuer {r.GetValue(deleteId)}?")) return 1;
            await api.DeleteIssuerAsync(new IssuerId(r.GetValue(deleteId)), ct);
            Console.WriteLine("Deleted.");
            return 0;
        }, deleteId, deleteYes);

        foreach (var (name, description, confirm) in new (string, string, string)[]
                 {
                     ("make-default", MakeDefaultHelp, "Make issuer {0} the default?"),
                     ("retire", RetireHelp, "Retire issuer {0}?"),
                     ("archive", ArchiveHelp, "Archive issuer {0} and delete its key?")
                 })
        {
            var id = new Argument<Guid>("id") { Description = "Issuer id (GUID, from 'qca issuers list')." };
            var yes = new Option<bool>("--yes") { Description = "Skip the confirmation prompt (default: ask; answering anything but y exits 1)." };
            var action = name;
            Sub(name, description, async (r, api, ct) =>
            {
                var issuerId = new IssuerId(r.GetValue(id));
                if (!r.GetValue(yes) && !Confirm(string.Format(System.Globalization.CultureInfo.InvariantCulture, confirm, issuerId))) return 1;
                var issuer = action switch
                {
                    "make-default" => await api.MakeIssuerDefaultAsync(issuerId, ct),
                    "retire" => await api.RetireIssuerAsync(issuerId, ct),
                    _ => await api.ArchiveIssuerAsync(issuerId, ct)
                };
                if (Json(r)) return CliApi.PrintJson(issuer);
                PrintIssuer(issuer);
                return 0;
            }, id, yes);
        }

        var exportKeyId = new Argument<Guid>("id") { Description = "Id of an Active or Retired online issuer (GUID, from 'qca issuers list')." };
        var exportKeyFile = new Option<string>("--file", "-f") { Description = "Where to write the private key PEM (required).", Required = true };
        var exportKeyYes = new Option<bool>("--yes") { Description = "Skip the confirmation prompt (default: ask; answering anything but y exits 1)." };
        Sub("export-key", ExportKeyHelp, async (r, api, ct) =>
        {
            return await ExportKeyAsync(api, new IssuerId(r.GetValue(exportKeyId)), r.GetValue(exportKeyFile)!, r.GetValue(exportKeyYes),
                Confirm, Console.Out, Console.Error, ct);
        }, exportKeyId, exportKeyFile, exportKeyYes);

        var exportPfxId = new Argument<Guid>("id") { Description = "Id of an Active or Retired online issuer (GUID, from 'qca issuers list')." };
        var exportPfxFile = new Option<string>("--file", "-f") { Description = "Where to write the PKCS#12 file (required).", Required = true };
        var exportPfxPassword = new Option<string>("--pfx-password") { Description = "Password protecting the PKCS#12 file (required, not empty).", Required = true };
        var exportPfxNoChain = new Option<bool>("--no-chain") { Description = "Leave the CAs above the issuer out of the file (default: include them, root last)." };
        var exportPfxYes = new Option<bool>("--yes") { Description = "Skip the confirmation prompt (default: ask; answering anything but y exits 1)." };
        Sub("export-pfx", ExportPfxHelp, async (r, api, ct) =>
        {
            return await ExportPfxAsync(api, new IssuerId(r.GetValue(exportPfxId)), r.GetValue(exportPfxFile)!, r.GetValue(exportPfxPassword),
                !r.GetValue(exportPfxNoChain), r.GetValue(exportPfxYes), Confirm, Console.Out, Console.Error, ct);
        }, exportPfxId, exportPfxFile, exportPfxPassword, exportPfxNoChain, exportPfxYes);

        var bundleFormat = new Option<string>("--format", "-F") { Description = "Bundle format: pem or p7b (default pem). Only the exact lowercase value pem prints to stdout; any other value needs --file (the server returns p7b for p7b in any case and PEM for anything else).", DefaultValueFactory = _ => "pem" };
        var bundleFile = new Option<string?>("--file", "-f") { Description = "Where to write the bundle (default: print PEM to stdout; required for p7b)." };
        Sub("trust-bundle", TrustBundleHelp, async (r, api, ct) =>
        {
            var format = r.GetValue(bundleFormat)!;
            var bytes = await api.DownloadTrustBundleAsync(format, ct);
            if (r.GetValue(bundleFile) is { } path) await File.WriteAllBytesAsync(path, bytes, ct);
            else if (format == "pem") Console.Write(System.Text.Encoding.ASCII.GetString(bytes));
            else { Console.Error.WriteLine("Binary output needs --file."); return 1; }
            return 0;
        }, bundleFormat, bundleFile);

        return cmd;
    }

    /// <summary>The create request described by the parsed options. Pure; pinned by IssuerCommandsTests.</summary>
    internal static CreateIntermediateRequest BuildCreateRequest(ParseResult result)
    {
        var pathLength = result.GetValue(PathLengthOption);
        return new CreateIntermediateRequest
        {
            Name = result.GetValue(NameOption)!,
            CommonName = result.GetValue(CnOption)!,
            OrganizationName = result.GetValue(OOption),
            OrganizationalUnit = result.GetValue(OuOption),
            Country = result.GetValue(COption),
            State = result.GetValue(StOption),
            Locality = result.GetValue(LOption),
            KeyAlgorithm = result.GetValue(AlgorithmOption) is { } a ? CertificateKeyAlgorithmExtensions.Parse(a) : null,
            ValidityDays = result.GetValue(ValidityOption),
            PathLength = string.Equals(pathLength, "none", StringComparison.OrdinalIgnoreCase) ? null : int.Parse(pathLength ?? "0", System.Globalization.CultureInfo.InvariantCulture),
            PermittedDnsSuffixes = [.. result.GetValue(PermitDnsOption) ?? []],
            ExcludedDnsSuffixes = [.. result.GetValue(ExcludeDnsOption) ?? []],
            PermittedIpRanges = [.. result.GetValue(PermitIpOption) ?? []],
            ExcludedIpRanges = [.. result.GetValue(ExcludeIpOption) ?? []],
            ParentIssuerId = result.GetValue(ParentOption) is { } parent ? new IssuerId(parent) : null
        };
    }

    internal static void PrintIssuer(IssuerResponse i)
    {
        static string List(IReadOnlyList<string> items) => items.Count == 0 ? "none" : string.Join(", ", items);
        PrintRow("Id", i.Id.ToString());
        PrintRow("Name", i.Name);
        PrintRow("Kind", i.Kind.ToString());
        PrintRow("Custody", i.KeyCustody.ToString());
        PrintRow("Status", i.Status + (i.IsDefault ? " (default)" : ""));
        PrintRow("Parent", i.ParentIssuerId?.ToString() ?? "none");
        PrintRow("Subject DN", i.SubjectDn);
        PrintRow("Algorithm", i.KeyAlgorithm);
        PrintRow("Valid", $"{i.ValidFrom:yyyy-MM-dd} to {i.ValidTo:yyyy-MM-dd}");
        PrintRow("Path length", i.PathLengthConstraint?.ToString() ?? "none");
        PrintRow("Permitted DNS", List(i.PermittedDnsSuffixes));
        PrintRow("Excluded DNS", List(i.ExcludedDnsSuffixes));
        PrintRow("Permitted IP", List(i.PermittedIpRanges));
        PrintRow("Excluded IP", List(i.ExcludedIpRanges));
        if (i.KeyCustody == IssuerKeyCustody.Offline)
            PrintRow("CRL", i.UploadedCrlNumber is null ? "not uploaded" : $"#{i.UploadedCrlNumber}, next update {i.UploadedCrlNextUpdateUtc:u}");
    }

    /// <summary>The <c>export-key</c> flow: warn, confirm, download, write. Testable without a process.</summary>
    internal static async Task<int> ExportKeyAsync(CertificateRequestsApiClient api, IssuerId id, string path, bool yes,
        Func<string, bool> confirm, TextWriter output, TextWriter error, CancellationToken ct)
    {
        await error.WriteLineAsync(KeyExportWarning);
        if (!yes && !confirm($"Download the private key of issuer {id}?")) return 1;
        return await WriteSecretAsync(path, await api.DownloadIssuerPrivateKeyAsync(id, ct), output, error, ct);
    }

    /// <summary>The <c>export-pfx</c> flow: refuse an empty password, warn, confirm, download, write.</summary>
    internal static async Task<int> ExportPfxAsync(CertificateRequestsApiClient api, IssuerId id, string path, string? password,
        bool includeChain, bool yes, Func<string, bool> confirm, TextWriter output, TextWriter error, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(password))
        {
            await error.WriteLineAsync("error: --pfx-password must not be empty.");
            return 1;
        }
        await error.WriteLineAsync(KeyExportWarning);
        if (!yes && !confirm($"Download issuer {id} with its private key?")) return 1;
        return await WriteSecretAsync(path, await api.DownloadIssuerPfxAsync(id, password, includeChain, ct), output, error, ct);
    }

    /// <summary>Writes key material to a new file only the owner can read (where the OS supports it); refuses to overwrite.</summary>
    private static async Task<int> WriteSecretAsync(string path, byte[] bytes, TextWriter output, TextWriter error, CancellationToken ct)
    {
        try
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            await using var stream = new FileStream(path, options);
            await stream.WriteAsync(bytes, ct);
        }
        catch (IOException ex)
        {
            await error.WriteLineAsync($"error: cannot write {path}: {ex.Message}");
            return 1;
        }
        await output.WriteLineAsync($"written   {path}");
        return 0;
    }

    internal static bool Confirm(string question)
    {
        Console.Write($"{question} [y/N] ");
        return string.Equals(Console.ReadLine()?.Trim(), "y", StringComparison.OrdinalIgnoreCase);
    }

    private static void PrintRow(string label, string? value) => Console.WriteLine($"{label,-14} {value}");

    private static string SafeFileName(string name) =>
        string.Concat(name.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '-')).Trim('-') is { Length: > 0 } safe ? safe : "intermediate";
}
