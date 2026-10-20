using FluentValidation;

namespace Qertum.Services.Validators;

internal sealed class UpdateCertificateRequestValidator : AbstractValidator<UpdateCertificateRequestRequest>
{
    public UpdateCertificateRequestValidator()
    {
        RuleFor(r => r.CommonName)
            .NotEmpty()
            .MaximumLength(200)
            .Must(cn => !CertificateRequestValidator.ContainsInvalidDnChars(cn))
            .WithMessage("CommonName contains invalid X.500 characters.");

        RuleFor(r => r.Type)
            .NotEmpty()
            .MaximumLength(50);

        RuleFor(r => r.PropertiesJson)
            .NotEmpty()
            .Custom((json, ctx) =>
            {
                if (!CertificateRequestValidator.ValidatePropertiesJson(json, out var error))
                    ctx.AddFailure(error ?? "Invalid properties JSON.");
            });

        RuleFor(r => r.ValidityDays)
            .GreaterThanOrEqualTo(1)
            .When(r => r.ValidityDays.HasValue)
            .WithMessage("ValidityDays must be at least 1 day.");
    }
}
