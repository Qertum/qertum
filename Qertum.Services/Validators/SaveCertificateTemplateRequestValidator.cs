using FluentValidation;

namespace Qertum.Services.Validators;

internal sealed class SaveCertificateTemplateRequestValidator : AbstractValidator<SaveCertificateTemplateRequest>
{
    public SaveCertificateTemplateRequestValidator()
    {
        RuleFor(r => r.Name).NotEmpty().MaximumLength(100);

        RuleFor(r => r.TypeKey)
            .NotEmpty()
            .MaximumLength(50)
            .Must((_, key, ctx) =>
            {
                if (CertificateRequestValidator.IsValidTypeKey(key, out var error))
                    return true;
                ctx.MessageFormatter.AppendArgument("Error", error ?? "Invalid TypeKey.");
                return false;
            })
            .WithMessage("{Error}");

        RuleFor(r => r.Description).MaximumLength(500).When(r => r.Description is not null);
        RuleFor(r => r.ValidityDays).GreaterThan(0).When(r => r.ValidityDays.HasValue);
    }
}
