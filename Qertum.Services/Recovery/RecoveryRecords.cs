using System.Globalization;
using System.Text.Json;

namespace Qertum.Services.Recovery;

/// <summary>
/// Reads and judges the two status files the host's backup and restore scripts write under
/// <c>{data}/recovery/</c>. Pure: no database, no clock of its own. Anything it cannot trust is
/// <see cref="RecoveryItemState.Unreadable"/> with a fixed explanation, never file content.
/// </summary>
internal static class RecoveryRecords
{
    internal const string DirectoryName = "recovery";
    internal const string BackupFileName = "last-backup.json";
    internal const string RestoreFileName = "last-restore.json";
    internal const int MaxFileBytes = 4096;
    private const int SupportedSchemaVersion = 1;
    private const string TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'";
    private static readonly TimeSpan FutureTolerance = TimeSpan.FromMinutes(5);

    internal static RecoveryStatus Evaluate(string dataDirectory, CaSettings settings, DateTime nowUtc) => new()
    {
        GeneratedAtUtc = nowUtc,
        Backup = Read(dataDirectory, BackupFileName, isRestore: false, TimeSpan.FromHours(settings.AttentionBackupMaxAgeHours), nowUtc),
        Restore = Read(dataDirectory, RestoreFileName, isRestore: true, TimeSpan.FromDays(settings.AttentionRestoreVerifiedMaxAgeDays), nowUtc)
    };

    private static RecoveryItem Read(string dataDirectory, string fileName, bool isRestore, TimeSpan limit, DateTime nowUtc)
    {
        var path = Path.Combine(dataDirectory, DirectoryName, fileName);
        var buffer = new byte[MaxFileBytes + 1];
        int read;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            read = stream.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return new RecoveryItem { State = RecoveryItemState.NotReported };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Unreadable("The file could not be read.");
        }

        if (read > MaxFileBytes)
            return Unreadable("The file is larger than 4 KiB.");

        try
        {
            using var document = JsonDocument.Parse(new ReadOnlyMemory<byte>(buffer, 0, read));
            return Judge(document.RootElement, isRestore, limit, nowUtc);
        }
        catch (JsonException)
        {
            return Unreadable("The file is not valid JSON.");
        }
    }

    private static RecoveryItem Judge(JsonElement root, bool isRestore, TimeSpan limit, DateTime nowUtc)
    {
        if (root.ValueKind != JsonValueKind.Object)
            return Unreadable("The file is not a JSON object.");
        if (!root.TryGetProperty("schemaVersion", out var version)
            || version.ValueKind != JsonValueKind.Number || !version.TryGetInt32(out var versionNumber)
            || versionNumber != SupportedSchemaVersion)
            return Unreadable("The schemaVersion is missing or not supported.");

        if (!TryText(root, "completedAtUtc", required: true, max: 20, out var completedText)
            || !DateTimeOffset.TryParseExact(completedText, TimestampFormat, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var completed))
            return Unreadable("The completion time is missing or not in the expected format.");
        var completedUtc = completed.UtcDateTime;
        if (completedUtc > nowUtc + FutureTolerance)
            return Unreadable("The completion time is in the future.");

        if (!TryText(root, "archiveName", required: false, max: 255, out var archiveName))
            return Unreadable("The archive name is not valid text.");
        if (!TryText(root, "reportedBy", required: false, max: 64, out var reportedBy))
            return Unreadable("The reportedBy value is not valid text.");

        long? sizeBytes = null;
        if (root.TryGetProperty("sizeBytes", out var size))
        {
            if (size.ValueKind != JsonValueKind.Number || !size.TryGetInt64(out var bytes) || bytes < 0)
                return Unreadable("The size is not a non-negative number.");
            sizeBytes = bytes;
        }

        string? kind = null, step = null, failedCheck = null;
        if (isRestore)
        {
            if (!TryText(root, "kind", required: true, max: 16, out kind)
                || kind is not ("performed" or "verified" or "usable" or "failed"))
                return Unreadable("The restore kind is missing or unknown.");

            if (kind == "failed"
                && (!TryText(root, "step", required: true, max: 16, out step) || step is not ("manifest" or "usability")
                    || !TryText(root, "failedCheck", required: true, max: 32, out failedCheck) || !failedCheck!.All(IsTokenCharacter)))
                return Unreadable("The failed restore record has no valid step and check.");
        }

        // A restore that was only performed proves nothing about whether recovery works, so it is shown with its
        // age but never compared with a limit. A failed test is never compared either: it stands until a passing
        // run replaces it.
        var judged = !isRestore || kind is "verified" or "usable";
        var state = kind == "failed" ? RecoveryItemState.Failed
            : !judged ? RecoveryItemState.NotJudged
            : nowUtc - completedUtc > limit ? RecoveryItemState.Stale
            : RecoveryItemState.Fresh;

        return new RecoveryItem
        {
            State = state,
            CompletedAtUtc = completedUtc,
            ArchiveName = archiveName,
            SizeBytes = sizeBytes,
            Kind = kind,
            Step = step,
            FailedCheck = failedCheck,
            ReportedBy = reportedBy,
            ThresholdHours = judged ? (int)limit.TotalHours : null
        };
    }

    private static bool IsTokenCharacter(char c) => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or ':' or '-';

    /// <summary>A string property of bounded length without control characters. Absent is fine unless required.</summary>
    private static bool TryText(JsonElement root, string name, bool required, int max, out string? value)
    {
        value = null;
        if (!root.TryGetProperty(name, out var element))
            return !required;
        if (element.ValueKind != JsonValueKind.String)
            return false;
        var text = element.GetString();
        if (string.IsNullOrEmpty(text) || text.Length > max || text.Any(char.IsControl))
            return false;
        value = text;
        return true;
    }

    private static RecoveryItem Unreadable(string problem) =>
        new() { State = RecoveryItemState.Unreadable, Problem = problem };
}
