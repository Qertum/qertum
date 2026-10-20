using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Validators;

namespace Qertum.Tests;

public sealed class CertificateMetadataTests
{
    private static readonly CertificateMetadataValidator Validator = new();

    [Fact]
    public void Normalize_TrimsAndTurnsBlankIntoNull()
    {
        var normalized = new CertificateMetadata { OwnerTeam = "  Platform  ", Purpose = "   ", TicketReference = "" }.Normalize();

        Assert.Equal("Platform", normalized.OwnerTeam);
        Assert.Null(normalized.Purpose);
        Assert.Null(normalized.TicketReference);
        Assert.Null(normalized.CompatibilityNote);
    }

    [Fact]
    public void ChangesTo_ListsOnlyTheFieldsThatDiffer()
    {
        var before = new CertificateMetadata { OwnerTeam = "A", Purpose = "x" };
        var after = new CertificateMetadata { OwnerTeam = "B", Purpose = "x", TicketReference = "OPS-1" };

        var changes = before.ChangesTo(after);

        Assert.Equal(["OwnerTeam", "TicketReference"], changes.Select(c => c.Field));
        Assert.Equal(("A", "B"), (changes[0].Before, changes[0].After));
        Assert.Null(changes[1].Before);
        Assert.Equal("OPS-1", changes[1].After);
        Assert.Empty(before.ChangesTo(before with { }));
    }

    [Theory]
    [InlineData(nameof(CertificateMetadata.OwnerTeam), 101)]
    [InlineData(nameof(CertificateMetadata.Purpose), 201)]
    [InlineData(nameof(CertificateMetadata.TargetSystem), 201)]
    [InlineData(nameof(CertificateMetadata.TicketReference), 101)]
    [InlineData(nameof(CertificateMetadata.CompatibilityNote), 501)]
    public void Validator_RejectsValuesOverTheirLimit_AndAcceptsTheLimit(string field, int tooLong)
    {
        Assert.False(Validator.Validate(With(field, new string('a', tooLong))).IsValid);
        Assert.True(Validator.Validate(With(field, new string('a', tooLong - 1))).IsValid);
    }

    [Theory]
    [InlineData("ops@contoso.local", true)]
    [InlineData("not-an-email", false)]
    [InlineData(null, true)]
    public void Validator_ChecksTheContactEmail(string? email, bool valid) =>
        Assert.Equal(valid, Validator.Validate(new CertificateMetadata { ContactEmail = email }).IsValid);

    [Fact]
    public void Validator_RejectsAnOverlongEmail() =>
        Assert.False(Validator.Validate(new CertificateMetadata { ContactEmail = new string('a', 250) + "@x.io" }).IsValid);

    [Theory]
    [InlineData(nameof(CertificateMetadata.OwnerTeam))]
    [InlineData(nameof(CertificateMetadata.Purpose))]
    [InlineData(nameof(CertificateMetadata.TargetSystem))]
    [InlineData(nameof(CertificateMetadata.TicketReference))]
    [InlineData(nameof(CertificateMetadata.CompatibilityNote))]
    public void Validator_RejectsKeyMaterialMarkers(string field)
    {
        var result = Validator.Validate(With(field, "see -----BEGIN PRIVATE KEY----- here"));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.PropertyName == field);
    }

    [Theory]
    [InlineData(nameof(CertificateMetadata.OwnerTeam), "line1\nline2")]
    [InlineData(nameof(CertificateMetadata.Purpose), "back\rspace")]
    [InlineData(nameof(CertificateMetadata.TargetSystem), "\u001b[2J clear")]
    [InlineData(nameof(CertificateMetadata.TicketReference), "nul\0byte")]
    [InlineData(nameof(CertificateMetadata.CompatibilityNote), "tab\there")]
    public void Validator_RejectsControlCharacters(string field, string value)
    {
        var result = Validator.Validate(With(field, value));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.PropertyName == field);
    }

    [Fact]
    public void Validator_RejectsControlCharactersInTheEmail() =>
        Assert.False(Validator.Validate(new CertificateMetadata { ContactEmail = "a\nb@contoso.local" }).IsValid);

    [Fact]
    public async Task Metadata_RoundTripsThroughTheDatabase_AndDefaultsToAllUnknown()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await MetadataTestHost.CreateAsync();
        var plain = host.Db.CertificateRequests.Add(new CertificateRequest { CommonName = "a.local", RequestedBy = "alice" }).Entity;
        var tagged = host.Db.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "b.local", RequestedBy = "alice",
            Metadata = new CertificateMetadata { OwnerTeam = "Platform", ContactEmail = "ops@contoso.local", CompatibilityNote = "Java 8" }
        }).Entity;
        await host.Db.SaveChangesAsync(ct);
        host.Db.ChangeTracker.Clear();

        var reloadedPlain = await host.Db.CertificateRequests.SingleAsync(r => r.Id == plain.Id, ct);
        var reloadedTagged = await host.Db.CertificateRequests.SingleAsync(r => r.Id == tagged.Id, ct);

        Assert.Equal(new CertificateMetadata(), reloadedPlain.Metadata);
        Assert.Equal("Platform", reloadedTagged.Metadata.OwnerTeam);
        Assert.Equal("ops@contoso.local", reloadedTagged.Metadata.ContactEmail);
        Assert.Equal("Java 8", reloadedTagged.Metadata.CompatibilityNote);
        Assert.Null(reloadedTagged.Metadata.Purpose);
    }

    private static CertificateMetadata With(string field, string value) => field switch
    {
        nameof(CertificateMetadata.OwnerTeam) => new() { OwnerTeam = value },
        nameof(CertificateMetadata.Purpose) => new() { Purpose = value },
        nameof(CertificateMetadata.TargetSystem) => new() { TargetSystem = value },
        nameof(CertificateMetadata.TicketReference) => new() { TicketReference = value },
        nameof(CertificateMetadata.CompatibilityNote) => new() { CompatibilityNote = value },
        _ => throw new ArgumentOutOfRangeException(nameof(field))
    };
}
