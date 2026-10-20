using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Qertum.Audit;

/// <summary>
/// The fields of an audit event the chain hash covers, exactly as written to the CLEF line (empty for null).
/// </summary>
/// <param name="EntryId">The <c>AuditEntryId</c> text.</param>
/// <param name="OccurredAt">The <c>OccurredAt</c> text (ISO 8601 round-trip, UTC).</param>
/// <param name="Action">The action name.</param>
/// <param name="PerformedBy">The acting identity.</param>
/// <param name="ResourceId">The resource id text, or empty.</param>
/// <param name="ResourceName">The resource name, or empty.</param>
/// <param name="Detail">The detail text, or empty.</param>
/// <param name="TraceId">The trace id, or empty.</param>
public readonly record struct AuditChainFields(
    string EntryId, string OccurredAt, string Action, string PerformedBy,
    string ResourceId, string ResourceName, string Detail, string TraceId);

/// <summary>Computes the hash that links one audit line to the previous line of the same writer.</summary>
public static class AuditChainHasher
{
    /// <summary>
    /// SHA-256 (lowercase hex) over the previous hash as ASCII (empty for the first entry), then each field
    /// 4-byte-big-endian length-prefixed as UTF-8, in order: entry id, occurred-at, action, performed-by,
    /// resource id, resource name, detail, trace id, writer, sequence (decimal).
    /// </summary>
    /// <param name="previousHash">The previous entry's hash, or null for the first.</param>
    /// <param name="writer">The writer (chain) name.</param>
    /// <param name="seq">The 1-based sequence number.</param>
    /// <param name="fields">The covered event fields.</param>
    public static string Compute(string? previousHash, string writer, long seq, in AuditChainFields fields)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.ASCII.GetBytes(previousHash ?? string.Empty));
        Span<byte> length = stackalloc byte[4];
        foreach (var field in new[]
                 {
                     fields.EntryId, fields.OccurredAt, fields.Action, fields.PerformedBy, fields.ResourceId,
                     fields.ResourceName, fields.Detail, fields.TraceId, writer, seq.ToString(CultureInfo.InvariantCulture)
                 })
        {
            var bytes = Encoding.UTF8.GetBytes(field);
            BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
            hash.AppendData(length);
            hash.AppendData(bytes);
        }

        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }
}
