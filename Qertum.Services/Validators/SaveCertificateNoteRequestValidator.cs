using FluentValidation;

namespace Qertum.Services.Validators;

internal sealed class SaveCertificateNoteRequestValidator : AbstractValidator<SaveCertificateNoteRequest>
{
    public SaveCertificateNoteRequestValidator()
    {
        RuleFor(r => r.Body)
            .Must(b => !string.IsNullOrWhiteSpace(b)).WithMessage("A note cannot be empty.")
            .Must(b => b is null || b.Trim().Length <= CertificateNote.MaxBodyLength)
                .WithMessage($"A note is at most {CertificateNote.MaxBodyLength} characters.")
            // qca prints notes, so a terminal escape or other control character would let one author forge what another reads.
            .Must(b => b is null || b.All(c => !char.IsControl(c) || c is '\n' or '\r' or '\t'))
                .WithMessage("A note is plain text: line breaks and tabs are allowed, other control characters are not.")
            .Must(b => b is null || !b.Contains("-----BEGIN", StringComparison.OrdinalIgnoreCase))
                .WithMessage("A note must not contain key material or certificate PEM.");
    }
}
