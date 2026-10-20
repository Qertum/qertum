using FluentValidation;

namespace Qertum.Services.Validators;

internal sealed class ImportCaRequestValidator : AbstractValidator<ImportCaRequest>
{
    public ImportCaRequestValidator()
    {
        RuleFor(r => r.CertificatePem).NotEmpty();
        RuleFor(r => r.PrivateKeyPem).NotEmpty();
    }
}
