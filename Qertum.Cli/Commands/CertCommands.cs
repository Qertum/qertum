using System.CommandLine;
using System.Security.Cryptography.X509Certificates;
using Qertum.Cli.Api;
using Qertum.Cli.Auth;
using Qertum.Services;

namespace Qertum.Cli.Commands;

internal static class CertCommands
{
    private const string KeyAccessRefused =
        "error: the private key could not be exported — only the certificate's requester or an administrator can export it.";

    public static Command Build(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var certCommand = new Command("cert", "Certificate commands");
        certCommand.Subcommands.Add(BuildInventory(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        certCommand.Subcommands.Add(BuildList(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        certCommand.Subcommands.Add(BuildDownloadCert(apiUrlOption, identityUrlOption, tokenOption));
        certCommand.Subcommands.Add(BuildDownloadKey(apiUrlOption, identityUrlOption, tokenOption));
        certCommand.Subcommands.Add(BuildRenew(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        certCommand.Subcommands.Add(BuildHistory(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        certCommand.Subcommands.Add(CertMetadataCommands.Build(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        certCommand.Subcommands.Add(CertNoteCommands.Build(apiUrlOption, identityUrlOption, tokenOption));
        return certCommand;
    }

    private static Command BuildInventory(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var cmd = new Command("inventory",
            "List every certificate Qertum issued with its real key, issuer signature, chain status and expiry.\n" +
            "\n" +
            "Reads only; changes nothing. Collects every page of the inventory API into one live, best-effort export. Facts are read from each certificate itself, so a malformed one shows Unknown rather than a guess; deployment compatibility is never asserted.\n" +
            "Needs: certificates.view.\n" +
            "Exit codes: 0 listed (also when empty); 1 not signed in, a call failed or the API was unreachable.\n" +
            "Output: a table with request id, leg, subject key, issuer signature, chain, status and expiry; --output json prints every inventory item.\n" +
            "Example: qca cert inventory --output json");
        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            return await CliApi.RunAsync(async () =>
            {
                var items = await CertificateInventoryExport.CollectAsync(CliApi.CreateClient(session),
                    cancellationToken: ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(items);

                if (items.Count == 0)
                {
                    Console.WriteLine("No issued certificates found.");
                    return 0;
                }

                Console.WriteLine($"{"Request ID",-36}  {"Leg",-7}  {"Subject Key",-24}  {"Issuer Signature",-28}  {"Chain",-20}  {"Status",-18}  Expires");
                foreach (var item in items)
                    Console.WriteLine($"{item.RequestId,-36}  {item.Leg,-7}  "
                        + $"{CliApi.Trunc(item.SubjectKeyAlgorithm, 24),-24}  "
                        + $"{CliApi.Trunc(item.IssuerSignatureAlgorithm, 28),-28}  "
                        + $"{item.ChainStatus,-20}  {item.Status,-18}  "
                        + (item.ValidToUtc?.ToString("yyyy-MM-dd") ?? "Unknown"));
                return 0;
            }, forbiddenHint: "requires certificates.view");
        });
        return cmd;
    }

    private static Command BuildList(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var statusOption = new Option<string>("--status")
        {
            Description = "Which certificates to list: issued, revoked, rejected, expired or all (every request in any status). Default: issued.",
            DefaultValueFactory = _ => "issued"
        };
        statusOption.Aliases.Add("-s");
        statusOption.AcceptOnlyFromAmong("issued", "revoked", "rejected", "expired", "all");

        var pageOption = new Option<int>("--page")
        {
            Description = "Page number, starting at 1. Default: 1.",
            DefaultValueFactory = _ => 1
        };

        var pageSizeOption = new Option<int>("--page-size")
        {
            Description = "Certificates per page. Default: 50.",
            DefaultValueFactory = _ => 50
        };

        var cmd = new Command("list",
            "List certificates by status, one page at a time.\n" +
            "\n" +
            "Reads only; changes nothing. Shows Unknown, never RSA, for a row with no stored key algorithm.\n" +
            "Needs: certificates.view.\n" +
            "Exit codes: 0 listed (also when nothing matches); 1 not signed in, a call failed or the API was unreachable.\n" +
            "Output: a table (revoked and all add revocation date and reason columns) and a page footer; --output json prints the whole paged result.\n" +
            "Example: qca cert list --status revoked --page-size 20");
        cmd.Options.Add(statusOption);
        cmd.Options.Add(pageOption);
        cmd.Options.Add(pageSizeOption);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            var status = result.GetValue(statusOption)!;
            var page = result.GetValue(pageOption);
            var pageSize = result.GetValue(pageSizeOption);

            return await CliApi.RunAsync(async () =>
            {
                var client = CliApi.CreateClient(session);
                var paged = status switch
                {
                    "issued" => await client.GetIssuedCertificatesAsync(page, pageSize, cancellationToken: ct),
                    "revoked" => await client.GetRevokedAsync(page, pageSize, ct),
                    "rejected" => await client.GetRejectedAsync(page, pageSize, ct),
                    "expired" => await client.GetExpiredAsync(page, pageSize, ct),
                    _ => await client.GetCertificateRequestsAsync(page, pageSize, cancellationToken: ct),
                };
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(paged);

                if (paged.Items.Count == 0)
                {
                    Console.WriteLine($"No {status} certificates found.");
                    return 0;
                }

                var showRevoked = status is "revoked" or "all";

                Console.WriteLine(
                    $"{"ID",-36}  {"Common Name",-28}  {"Type",-14}  {"Key Algorithm",-17}  {"Status",-11}  " +
                    (showRevoked ? $"{"Revoked At",-12}  {"Reason",-20}" : $"{"Valid From",-11}  {"Valid To",-11}"));
                Console.WriteLine(new string('-', showRevoked ? 147 : 143));

                foreach (var item in paged.Items)
                {
                    Console.Write(
                        $"{item.Id,-36}  " +
                        $"{CliApi.Trunc(item.CommonName, 28),-28}  " +
                        $"{CliApi.Trunc(item.Type, 14),-14}  " +
                        $"{(item.KeyAlgorithm?.ToCanonicalString() ?? CertificateAlgorithmLines.Unknown),-17}  " +
                        $"{item.Status,-11}  ");

                    if (showRevoked)
                        Console.WriteLine(
                            $"{(item.RevokedAtUtc?.ToString("yyyy-MM-dd") ?? "-"),-12}  " +
                            $"{CliApi.Trunc(item.RevocationReason, 20),-20}");
                    else
                        Console.WriteLine(
                            $"{(item.ValidFrom?.ToString("yyyy-MM-dd") ?? "-"),-11}  " +
                            $"{(item.ValidTo?.ToString("yyyy-MM-dd") ?? "-"),-11}");
                }

                Console.WriteLine();
                Console.WriteLine($"Page {paged.Page}/{paged.TotalPages}  ({paged.TotalCount} total)");
                return 0;
            });
        });

        return cmd;
    }

    private static Command BuildDownloadCert(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption)
    {
        var idArg = new Argument<Guid>("id") { Description = "Certificate request ID (GUID) of an Issued request. Required." };

        var outOption = new Option<string?>("--out")
        {
            Description = "Output file path, or '-' for stdout. Default: <common-name>.<ext> in the current directory; an existing file is overwritten."
        };
        outOption.Aliases.Add("-f");

        var formatOption = new Option<string>("--format")
        {
            Description = "Output format: pem, crt (PEM text), cer (DER binary), p7b (PKCS#7, certificate only) or pfx (PKCS#12, bundles the private key and the CA chain). Default: pem. pfx needs owner or admin access.",
            DefaultValueFactory = _ => "pem"
        };
        formatOption.Aliases.Add("-F");
        formatOption.AcceptOnlyFromAmong("pem", "crt", "cer", "p7b", "pfx");

        var pfxPasswordOption = new Option<string>("--pfx-password")
        {
            Description = "Password protecting the PFX archive; used only with --format pfx. Default: empty (no password).",
            DefaultValueFactory = _ => ""
        };

        var pqcOption = new Option<bool>("--pqc")
        {
            Description = "Download the second certificate of a paired request instead of the first (with pfx, its key): the PQC certificate of a hybrid pair, or the encryption certificate of a signing + encryption pair. Default: off; fails on requests that are not paired."
        };

        var cmd = new Command("download-cert",
            "Download an issued certificate as PEM, CRT, CER, PKCS#7 or PKCS#12 and print its subject key and issuer signature.\n" +
            "\n" +
            "Creates a local file (or writes to stdout with --out -). Changes nothing on the server except, for --format pfx, an audited key export (PfxExported). Only an Issued request can be downloaded. pem, crt, cer and p7b carry the certificate only and never a private key; pfx bundles the private key and is refused unless you are the requester or an admin.\n" +
            "Needs: certificates.view (plus being the requester or an admin for --format pfx).\n" +
            "Exit codes: 0 written; 1 not signed in, request not found, not Issued, no certificate or key available, access to the key refused, or conversion failed.\n" +
            "Output: 'written <path>' and the algorithm lines on stdout (on stderr when the certificate itself goes to stdout); no JSON output.\n" +
            "Example: qca cert download-cert 3f2c9a1e-0000-0000-0000-000000000000 --format pem --out www.pem");
        cmd.Arguments.Add(idArg);
        cmd.Options.Add(outOption);
        cmd.Options.Add(formatOption);
        cmd.Options.Add(pfxPasswordOption);
        cmd.Options.Add(pqcOption);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            var id = new CertificateRequestId(result.GetValue(idArg));
            var outPath = result.GetValue(outOption);
            var format = (result.GetValue(formatOption) ?? "pem").ToLowerInvariant();
            var pqc = result.GetValue(pqcOption);

            return await CliApi.RunAsync(async () =>
            {
                var client = CliApi.CreateClient(session);
                var req = await client.GetByIdAsync(id, ct);
                if (req is null)
                {
                    await Console.Error.WriteLineAsync($"error: no certificate request with ID {id}.");
                    return 1;
                }

                if (req.Status != CertificateRequestStatus.Issued)
                {
                    await Console.Error.WriteLineAsync($"error: certificate is not issued (status: {req.Status})");
                    return 1;
                }

                var certPem = pqc ? req.PqcCertificatePem : req.CertificatePem;
                if (string.IsNullOrWhiteSpace(certPem))
                {
                    await Console.Error.WriteLineAsync(pqc
                        ? "error: no PQC certificate on this request — is it a paired request?"
                        : "error: certificate PEM is not available");
                    return 1;
                }

                // PFX bundles the private key, which the API only releases to the certificate's owner
                // (or an administrator) and never includes in the request body. The archive is therefore
                // assembled server-side and downloaded whole.
                byte[]? serverPfx = null;
                if (format == "pfx")
                {
                    if (!(pqc ? req.HasPqcPrivateKey : req.HasPrivateKey))
                    {
                        await Console.Error.WriteLineAsync(pqc
                            ? "error: no PQC private key on this request — is it a paired request?"
                            : "error: private key is not available (required for PFX format)");
                        return 1;
                    }

                    if (CertificateAlgorithmLines.Pkcs12Note(req.KeyAlgorithm?.ToCanonicalString(), pqc) is { } pkcs12Note)
                        await Console.Error.WriteLineAsync(pkcs12Note);

                    serverPfx = await client.DownloadPfxAsync(id, result.GetValue(pfxPasswordOption), pqc, includeChain: true, ct);
                    if (serverPfx is null)
                    {
                        await Console.Error.WriteLineAsync(KeyAccessRefused);
                        return 1;
                    }
                }

                var ext = format switch
                {
                    "cer" => ".cer",
                    "crt" => ".crt",
                    "p7b" => ".p7b",
                    "pfx" => ".pfx",
                    _     => ".pem"
                };
                var defaultName = $"{SanitizeFilename(req.CommonName)}{(pqc ? "-pqc" : "")}{ext}";
                var keyAlgorithm = req.KeyAlgorithm?.ToCanonicalString();

                // Subject key and issuer signature are two facts; printing neither leaves an operator to
                // read the issuer's algorithm as the certificate's. Sent to stderr when the certificate
                // itself goes to stdout, so a pipe receives only the certificate.
                async Task DescribeAsync(TextWriter writer)
                {
                    foreach (var line in CertificateAlgorithmLines.Describe(keyAlgorithm, pqc, certPem))
                        await writer.WriteLineAsync(line);
                }

                try
                {
                    if (format is "pem" or "crt")
                    {
                        if (outPath == "-")
                        {
                            Console.Write(certPem);
                            await DescribeAsync(Console.Error);
                            return 0;
                        }
                        var path = outPath ?? defaultName;
                        await File.WriteAllTextAsync(path, certPem, ct);
                        await Console.Out.WriteLineAsync($"written   {path}");
                        await DescribeAsync(Console.Out);
                        return 0;
                    }

                    byte[] bytes;
                    switch (format)
                    {
                        case "cer":
                        {
                            using var cert = X509Certificate2.CreateFromPem(certPem);
                            bytes = cert.Export(X509ContentType.Cert);
                            break;
                        }
                        case "p7b":
                        {
                            using var cert = X509Certificate2.CreateFromPem(certPem);
                            bytes = new X509Certificate2Collection(cert).Export(X509ContentType.Pkcs7)!;
                            break;
                        }
                        default: // pfx — already assembled by the API
                            bytes = serverPfx!;
                            break;
                    }

                    if (outPath == "-")
                    {
                        await using var stdout = Console.OpenStandardOutput();
                        await stdout.WriteAsync(bytes, ct);
                        await DescribeAsync(Console.Error);
                        return 0;
                    }

                    var filePath = outPath ?? defaultName;
                    await File.WriteAllBytesAsync(filePath, bytes, ct);
                    await Console.Out.WriteLineAsync($"written   {filePath}");
                    await DescribeAsync(Console.Out);
                    return 0;
                }
                catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or ArgumentException)
                {
                    await Console.Error.WriteLineAsync($"error: certificate conversion failed — {ex.Message}");
                    return 1;
                }
            });
        });

        return cmd;
    }

    private static Command BuildDownloadKey(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption)
    {
        var idArg = new Argument<Guid>("id") { Description = "Certificate request ID (GUID) of an Issued request. Required." };

        var outOption = new Option<string?>("--out")
        {
            Description = "Output file path, or '-' for stdout. Default: <common-name>.key in the current directory; an existing file is overwritten."
        };
        outOption.Aliases.Add("-f");

        var pqcOption = new Option<bool>("--pqc")
        {
            Description = "Download the private key of the second certificate of a paired request instead of the first: the PQC key of a hybrid pair, or the encryption key of a signing + encryption pair. Default: off; fails on requests that are not paired."
        };

        var cmd = new Command("download-key",
            "Download the private key PEM of an issued request the CA generated.\n" +
            "\n" +
            "Creates a local file (or writes to stdout with --out -) holding an unencrypted private key. Changes server records only by auditing: every download is audited (PrivateKeyDownloaded) and announced to KeyAccess webhooks. Not available for requests issued from a client CSR (ACME, EST), because the CA never held that key.\n" +
            "Needs: being the requester of the certificate or an admin (and certificates.view, which every certificate-request route requires).\n" +
            "Exit codes: 0 written; 1 not signed in, request not found, not Issued, no stored key, or access refused.\n" +
            "Output: 'written <path>'; with --out - only the key on stdout. No JSON output.\n" +
            "Example: qca cert download-key 3f2c9a1e-0000-0000-0000-000000000000 --out www.key");
        cmd.Arguments.Add(idArg);
        cmd.Options.Add(outOption);
        cmd.Options.Add(pqcOption);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            var id = new CertificateRequestId(result.GetValue(idArg));
            var outPath = result.GetValue(outOption);
            var pqc = result.GetValue(pqcOption);

            return await CliApi.RunAsync(async () =>
            {
                var client = CliApi.CreateClient(session);
                var req = await client.GetByIdAsync(id, ct);
                if (req is null)
                {
                    await Console.Error.WriteLineAsync($"error: no certificate request with ID {id}.");
                    return 1;
                }

                if (req.Status != CertificateRequestStatus.Issued)
                {
                    await Console.Error.WriteLineAsync($"error: certificate is not issued (status: {req.Status})");
                    return 1;
                }

                if (!(pqc ? req.HasPqcPrivateKey : req.HasPrivateKey))
                {
                    await Console.Error.WriteLineAsync(pqc
                        ? "error: no PQC private key on this request — is it a paired request?"
                        : "error: private key PEM is not available");
                    return 1;
                }

                // The key is never part of the request body: it comes from a dedicated endpoint that
                // authorizes the caller as the certificate's owner (or an administrator).
                var pem = await client.DownloadPrivateKeyAsync(id, pqc, ct);
                if (pem is null)
                {
                    await Console.Error.WriteLineAsync(KeyAccessRefused);
                    return 1;
                }

                if (outPath == "-")
                {
                    await using var stdout = Console.OpenStandardOutput();
                    await stdout.WriteAsync(pem, ct);
                    return 0;
                }

                var filePath = outPath ?? $"{SanitizeFilename(req.CommonName)}{(pqc ? "-pqc" : "")}.key";
                await File.WriteAllBytesAsync(filePath, pem, ct);
                await Console.Out.WriteLineAsync($"written   {filePath}");
                return 0;
            });
        });

        return cmd;
    }

    private static Command BuildHistory(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var idArg = new Argument<Guid>("id") { Description = "Certificate request ID (GUID). Required." };

        var cmd = new Command("history",
            "Show the lifecycle history of one certificate request: events, renewals, webhook deliveries and ACME order history.\n" +
            "\n" +
            "Reads only; changes nothing. Sections you may not see (webhook deliveries and diagnostics need settings.edit, key exports need owner or admin) are listed as 'withheld'.\n" +
            "Needs: certificates.view.\n" +
            "Exit codes: 0 shown; 1 not signed in, request not found, a call failed or the API was unreachable.\n" +
            "Output: a time-ordered table and withheld notes; --output json prints the full timeline contract.\n" +
            "Example: qca cert history 3f2c9a1e-0000-0000-0000-000000000000");
        cmd.Arguments.Add(idArg);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            return await CliApi.RunAsync(async () =>
            {
                var timeline = await CliApi.CreateClient(session).GetTimelineAsync(result.GetValue(idArg), ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(timeline);

                Console.WriteLine($"{timeline.Subject.CommonName}  ({timeline.Subject.Status}, serial {timeline.Subject.SerialNumber ?? "-"})");
                if (timeline.Completeness == TimelineCompleteness.PartialBeforeUpgrade)
                    Console.WriteLine("note: this certificate predates event recording; earlier steps come from its own record.");
                Console.WriteLine();
                Console.WriteLine($"{"When (UTC)",-17}  {"Kind",-15}  {"Action",-24}  {"By",-20}  Detail");
                Console.WriteLine(new string('-', 110));
                foreach (var entry in timeline.Entries)
                    Console.WriteLine(
                        $"{entry.OccurredAtUtc:yyyy-MM-dd HH:mm}  {entry.Kind,-15}  {CliApi.Trunc(entry.Action, 24),-24}  " +
                        $"{CliApi.Trunc(entry.PerformedBy, 20),-20}  {entry.Category}{(entry.Category is null ? "" : " ")}" +
                        $"{(entry.Kind == TimelineEntryKind.Note ? CertNoteCommands.DescribeForHistory(entry) : entry.Detail)}");
                foreach (var withheld in timeline.Withheld)
                    Console.WriteLine($"withheld: {withheld.Section} ({withheld.Count})");
                return 0;
            });
        });

        return cmd;
    }

    private static Command BuildRenew(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var idArg = new Argument<Guid>("id") { Description = "Certificate request ID (GUID) of the certificate to renew. Required." };

        var cmd = new Command("renew",
            "Create a renewal request for a certificate, copying its common name, type, algorithm, SANs and validity.\n" +
            "\n" +
            "Creates a new Pending request linked to the original; the original is untouched and the new one still needs approval. Issuance policy is re-evaluated, and the post-quantum stage may refuse or warn.\n" +
            "A CA-capable certificate (for example a SubordinateCA) also needs the certificates.ca permission to renew (refusal rule 'caPermission'), and its approval needs an independent approver. CA certificates are never auto-renewed: renewing one is always this deliberate step.\n" +
            "Needs: certificates.create (plus certificates.ca for CA-capable certificates; and certificates.view, which every certificate-request route requires).\n" +
            "Exit codes: 0 renewal request created; 1 not signed in, request not found, refused by policy or a call failed.\n" +
            "Output: the new request id, common name, type, algorithm and status; --output json prints the new request. Policy warnings go to stderr.\n" +
            "Example: qca cert renew 3f2c9a1e-0000-0000-0000-000000000000");
        cmd.Arguments.Add(idArg);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            var id = new CertificateRequestId(result.GetValue(idArg));
            return await CliApi.RunAsync(async () =>
            {
                var renewal = await CliApi.CreateClient(session).RenewAsync(id, ct);
                if (renewal is null)
                {
                    await Console.Error.WriteLineAsync($"error: no certificate request with ID {id}.");
                    return 1;
                }

                await CliApi.PrintWarningsAsync(renewal.Warnings);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(renewal);

                Console.WriteLine($"renewed   {renewal.Id}");
                Console.WriteLine($"  Common Name  : {renewal.CommonName}");
                Console.WriteLine($"  Type         : {renewal.Type}");
                Console.WriteLine($"  Algorithm    : {renewal.KeyAlgorithm?.ToCanonicalString() ?? CertificateAlgorithmLines.Unknown}");
                Console.WriteLine($"  Status       : {renewal.Status}");
                Console.WriteLine($"  Renewed From : {id}");
                return 0;
            });
        });

        return cmd;
    }

    private static string SanitizeFilename(string name)
    {
        var invalid = Path.GetInvalidFileNameChars();
        return string.Concat(name.Select(c => Array.IndexOf(invalid, c) >= 0 ? '_' : c));
    }
}
