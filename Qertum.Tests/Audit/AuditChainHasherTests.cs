using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Qertum.Audit;

namespace Qertum.Tests.Audit;

public sealed class AuditChainHasherTests
{
    private static readonly AuditChainFields Fields = new(
        "7f0c1c1e-0000-4000-8000-000000000001", "2026-10-14T12:00:00.0000000Z", "CertificateRevoked", "alice",
        "7f0c1c1e-0000-4000-8000-000000000002", "web.example.com", "keyCompromise", "0123456789abcdef0123456789abcdef");

    // An independent construction of the documented byte layout: prev as ASCII, then each field length-prefixed.
    private static string Reference(string? prev, string writer, long seq, AuditChainFields f)
    {
        using var ms = new MemoryStream();
        ms.Write(Encoding.ASCII.GetBytes(prev ?? string.Empty));
        foreach (var field in new[] { f.EntryId, f.OccurredAt, f.Action, f.PerformedBy, f.ResourceId, f.ResourceName, f.Detail, f.TraceId, writer, seq.ToString() })
        {
            var bytes = Encoding.UTF8.GetBytes(field);
            var length = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
            ms.Write(length);
            ms.Write(bytes);
        }

        return Convert.ToHexStringLower(SHA256.HashData(ms.ToArray()));
    }

    [Fact]
    public void Compute_MatchesTheDocumentedByteLayout()
    {
        Assert.Equal(Reference(null, "qertum.apiservice", 1, Fields), AuditChainHasher.Compute(null, "qertum.apiservice", 1, Fields));
        Assert.Equal(Reference(new string('a', 64), "qertum.apiservice", 2, Fields), AuditChainHasher.Compute(new string('a', 64), "qertum.apiservice", 2, Fields));
    }

    [Fact]
    public void Compute_ChangesWithEveryCoveredInput()
    {
        var baseline = AuditChainHasher.Compute(new string('a', 64), "w", 5, Fields);
        var variants = new[]
        {
            AuditChainHasher.Compute(new string('b', 64), "w", 5, Fields),
            AuditChainHasher.Compute(new string('a', 64), "x", 5, Fields),
            AuditChainHasher.Compute(new string('a', 64), "w", 6, Fields),
            AuditChainHasher.Compute(new string('a', 64), "w", 5, Fields with { EntryId = "other" }),
            AuditChainHasher.Compute(new string('a', 64), "w", 5, Fields with { OccurredAt = "2026-10-14T12:00:01.0000000Z" }),
            AuditChainHasher.Compute(new string('a', 64), "w", 5, Fields with { Action = "CertificateIssued" }),
            AuditChainHasher.Compute(new string('a', 64), "w", 5, Fields with { PerformedBy = "bob" }),
            AuditChainHasher.Compute(new string('a', 64), "w", 5, Fields with { ResourceId = "" }),
            AuditChainHasher.Compute(new string('a', 64), "w", 5, Fields with { ResourceName = "other" }),
            AuditChainHasher.Compute(new string('a', 64), "w", 5, Fields with { Detail = "changed" }),
            AuditChainHasher.Compute(new string('a', 64), "w", 5, Fields with { TraceId = "" })
        };

        Assert.All(variants, v => Assert.NotEqual(baseline, v));
        Assert.Equal(variants.Length, variants.Distinct().Count());
    }

    [Fact]
    public void Compute_LengthPrefixesFields_SoMovingTextBetweenNeighboursChangesTheHash()
    {
        var a = AuditChainHasher.Compute(null, "w", 1, Fields with { Action = "ab", PerformedBy = "c" });
        var b = AuditChainHasher.Compute(null, "w", 1, Fields with { Action = "a", PerformedBy = "bc" });

        Assert.NotEqual(a, b);
    }
}
