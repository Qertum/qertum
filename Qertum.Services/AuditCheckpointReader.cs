using Microsoft.Extensions.Options;
using Qertum.Audit;

namespace Qertum.Services;

/// <summary>
/// Reads the head of every audit chain from the CLEF files: the CA's audit directory and, when present, the
/// IdentityService one. Scans only the newest <see cref="MaxFilesPerLog"/> files of each log, so a writer silent
/// for longer than that is absent from the checkpoint.
/// </summary>
public sealed class AuditCheckpointReader(IOptions<AuditLogOptions> options, SecretStorageOptions storage, TimeProvider timeProvider)
{
    /// <summary>How many rolled files of one log are scanned for chain heads.</summary>
    public const int MaxFilesPerLog = 30;

    private readonly AuditLogOptions _options = options.Value;

    /// <summary>Reads every chain head now.</summary>
    public AuditCheckpoint Read()
    {
        var heads = new Dictionary<string, AuditChainHead>(StringComparer.Ordinal);
        foreach (var pattern in Patterns())
            foreach (var file in AuditLogFiles.NewestFirst(pattern).Take(MaxFilesPerLog))
                Scan(file, heads);

        return new AuditCheckpoint
        {
            GeneratedAtUtc = timeProvider.GetUtcNow().UtcDateTime,
            Chains = heads.Values.OrderBy(h => h.Writer, StringComparer.Ordinal).ToList()
        };
    }

    private IEnumerable<string> Patterns()
    {
        if (!string.IsNullOrEmpty(_options.File.Path))
            yield return _options.File.Path;

        var identity = string.IsNullOrWhiteSpace(_options.Checkpoint.IdentityDirectory)
            ? Path.Combine(storage.DataDirectory, "identity", "audit-logs")
            : _options.Checkpoint.IdentityDirectory;
        if (Directory.Exists(identity))
            yield return Path.Combine(identity, "identity-audit-.clef");
    }

    private static void Scan(string file, Dictionary<string, AuditChainHead> heads)
    {
        try
        {
            using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream);
            while (reader.ReadLine() is { } line)
            {
                if (AuditEventFormat.TryParseChain(line) is not { } link)
                    continue;
                if (!heads.TryGetValue(link.Writer, out var current) || link.Seq > current.Seq)
                    heads[link.Writer] = new AuditChainHead { Writer = link.Writer, Seq = link.Seq, Hash = link.Hash };
            }
        }
        catch (IOException)
        {
            // A file that is locked or deleted mid-scan is skipped; the next checkpoint reads it.
        }
    }
}
