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

        // The same reader issuance uses (TemplateExtensionSettings), so whatever a save accepts can
        // be issued from, and nothing the generator would drop gets stored.
        ReadableBy(r => r.KeyUsagesJson, TemplateExtensionSettings.ReadKeyUsages);
        ReadableBy(r => r.ExtendedKeyUsagesJson, TemplateExtensionSettings.ReadExtendedKeyUsages);
        ReadableBy(r => r.SanTypesJson, TemplateExtensionSettings.ReadSanTypes);
        ReadableBy(r => r.CustomExtensionsJson, TemplateExtensionSettings.ReadCustomExtensions);
    }

    private delegate object? Reader(string? json, out string? error);

    private void ReadableBy(System.Linq.Expressions.Expression<Func<SaveCertificateTemplateRequest, string?>> field, Reader read) =>
        RuleFor(field)
            .Must((_, json, ctx) =>
            {
                if (read(json, out var error) is not null)
                    return true;
                ctx.MessageFormatter.AppendArgument("Error", error);
                return false;
            })
            .WithMessage("{Error}");
}
