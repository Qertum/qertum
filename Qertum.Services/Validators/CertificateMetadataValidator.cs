using FluentValidation;

namespace Qertum.Services.Validators;

internal sealed class CertificateMetadataValidator : AbstractValidator<CertificateMetadata>
{
    private const string PemMarker = "-----BEGIN";
    private const string ControlCharacterMessage = "Metadata must be plain text: no line breaks, tabs or other control characters.";

    // These values are printed by qca and written into audit text, so a terminal escape or a line break
    // would let one person forge what another reads.
    private static bool NoControlCharacters(string? value) => value is null || !value.Any(char.IsControl);

    public CertificateMetadataValidator()
    {
        Text(nameof(CertificateMetadata.OwnerTeam), m => m.OwnerTeam, CertificateMetadata.OwnerTeamMax);
        Text(nameof(CertificateMetadata.Purpose), m => m.Purpose, CertificateMetadata.PurposeMax);
        Text(nameof(CertificateMetadata.TargetSystem), m => m.TargetSystem, CertificateMetadata.TargetSystemMax);
        Text(nameof(CertificateMetadata.TicketReference), m => m.TicketReference, CertificateMetadata.TicketReferenceMax);
        Text(nameof(CertificateMetadata.CompatibilityNote), m => m.CompatibilityNote, CertificateMetadata.CompatibilityNoteMax);

        RuleFor(m => m.ContactEmail == null ? null : m.ContactEmail.Trim())
            .MaximumLength(CertificateMetadata.ContactEmailMax)
            .OverridePropertyName(nameof(CertificateMetadata.ContactEmail))
            .Must(NoControlCharacters)
            .WithMessage(ControlCharacterMessage)
            .EmailAddress()
            .When(m => !string.IsNullOrWhiteSpace(m.ContactEmail));
    }

    // Lengths are checked after trimming (what is stored), and a PEM marker is refused so a pasted key never lands here.
    private void Text(string name, Func<CertificateMetadata, string?> value, int max) =>
        RuleFor(m => value(m) == null ? null : value(m)!.Trim())
            .MaximumLength(max)
            .OverridePropertyName(name)
            .Must(NoControlCharacters)
            .WithMessage(ControlCharacterMessage)
            .Must(v => v is null || !v.Contains(PemMarker, StringComparison.OrdinalIgnoreCase))
            .WithMessage("Metadata must not contain key material or certificate PEM.");
}
