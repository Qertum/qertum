namespace Qertum.Services;

/// <summary>One field of <see cref="CertificateMetadata"/> that an edit changed.</summary>
/// <param name="Field">The property name.</param>
/// <param name="Before">The previous value, or null when it was Unknown.</param>
/// <param name="After">The new value, or null when it is now Unknown.</param>
public readonly record struct MetadataChange(string Field, string? Before, string? After);

/// <summary>
/// Facts people or systems record about a certificate: who owns it, what it is for and where it runs.
/// Every field is optional and null means Unknown, never inferred. It never holds key material or secrets,
/// and <see cref="ContactEmail"/> is a notification contact only: it grants no access and does not replace
/// the requester identity.
/// </summary>
public sealed record CertificateMetadata
{
    /// <summary>Longest <see cref="OwnerTeam"/>.</summary>
    public const int OwnerTeamMax = 100;
    /// <summary>Longest <see cref="ContactEmail"/>.</summary>
    public const int ContactEmailMax = 254;
    /// <summary>Longest <see cref="Purpose"/>.</summary>
    public const int PurposeMax = 200;
    /// <summary>Longest <see cref="TargetSystem"/>.</summary>
    public const int TargetSystemMax = 200;
    /// <summary>Longest <see cref="TicketReference"/>.</summary>
    public const int TicketReferenceMax = 100;
    /// <summary>Longest <see cref="CompatibilityNote"/>.</summary>
    public const int CompatibilityNoteMax = 500;

    /// <summary>The team that owns the certificate.</summary>
    public string? OwnerTeam { get; init; }

    /// <summary>Where expiry and renewal notifications go; not an authorization-bearing identity.</summary>
    public string? ContactEmail { get; init; }

    /// <summary>What the certificate is for.</summary>
    public string? Purpose { get; init; }

    /// <summary>The system the certificate is deployed to.</summary>
    public string? TargetSystem { get; init; }

    /// <summary>A ticket or change reference, plain text (never fetched).</summary>
    public string? TicketReference { get; init; }

    /// <summary>Known compatibility facts; null reads as Unknown.</summary>
    public string? CompatibilityNote { get; init; }

    /// <summary>A copy with every value trimmed and blank values turned into null.</summary>
    public CertificateMetadata Normalize() => new()
    {
        OwnerTeam = Clean(OwnerTeam), ContactEmail = Clean(ContactEmail), Purpose = Clean(Purpose),
        TargetSystem = Clean(TargetSystem), TicketReference = Clean(TicketReference),
        CompatibilityNote = Clean(CompatibilityNote)
    };

    /// <summary>The fields whose value differs between this set and <paramref name="next"/>, in declaration order.</summary>
    public IReadOnlyList<MetadataChange> ChangesTo(CertificateMetadata next)
    {
        var changes = new List<MetadataChange>();
        void Check(string field, string? before, string? after)
        {
            if (!string.Equals(before, after, StringComparison.Ordinal)) changes.Add(new MetadataChange(field, before, after));
        }
        Check(nameof(OwnerTeam), OwnerTeam, next.OwnerTeam);
        Check(nameof(ContactEmail), ContactEmail, next.ContactEmail);
        Check(nameof(Purpose), Purpose, next.Purpose);
        Check(nameof(TargetSystem), TargetSystem, next.TargetSystem);
        Check(nameof(TicketReference), TicketReference, next.TicketReference);
        Check(nameof(CompatibilityNote), CompatibilityNote, next.CompatibilityNote);
        return changes;
    }

    private static string? Clean(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
