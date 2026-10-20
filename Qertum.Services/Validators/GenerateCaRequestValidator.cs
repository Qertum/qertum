using FluentValidation;

namespace Qertum.Services.Validators;

internal sealed class GenerateCaRequestValidator : AbstractValidator<GenerateCaRequest>
{
    public GenerateCaRequestValidator()
    {
        RuleFor(r => r.CommonName)
            .NotEmpty()
            .MaximumLength(200)
            .Must(cn => !CertificateRequestValidator.ContainsInvalidDnChars(cn))
            .WithMessage("CommonName contains invalid X.500 characters.");

        RuleFor(r => r.OrganizationName)
            .MaximumLength(200)
            .Must(v => !CertificateRequestValidator.ContainsInvalidDnChars(v))
            .WithMessage("OrganizationName contains invalid X.500 characters.")
            .When(r => r.OrganizationName is not null);

        RuleFor(r => r.OrganizationalUnit)
            .MaximumLength(200)
            .Must(v => !CertificateRequestValidator.ContainsInvalidDnChars(v))
            .WithMessage("OrganizationalUnit contains invalid X.500 characters.")
            .When(r => r.OrganizationalUnit is not null);

        RuleFor(r => r.State)
            .MaximumLength(200)
            .Must(v => !CertificateRequestValidator.ContainsInvalidDnChars(v))
            .WithMessage("State contains invalid X.500 characters.")
            .When(r => r.State is not null);

        RuleFor(r => r.Locality)
            .MaximumLength(200)
            .Must(v => !CertificateRequestValidator.ContainsInvalidDnChars(v))
            .WithMessage("Locality contains invalid X.500 characters.")
            .When(r => r.Locality is not null);

        RuleFor(r => r.Country)
            .MaximumLength(2)
            .Must(c => CertificateRequestValidator.ValidCountryCodes.Contains(c!))
            .WithMessage("Country must be a valid ISO 3166-1 alpha-2 code.")
            .When(r => !string.IsNullOrWhiteSpace(r.Country));

        RuleFor(r => r.ValidityDays).InclusiveBetween(1, 36500);

        // The root's key signs everything the CA issues. Refused here, as a 400 at POST
        // /ca/generate, rather than by AlgorithmStrategyFactory.CreateIssuer throwing in the queue
        // consumer after a RootCA request has already been filed and approved.
        RuleFor(r => r.KeyAlgorithm)
            .Must(a => a is null || (a.Value.CanSign() && a.Value.GetFamily() != AlgorithmFamily.Hybrid))
            .WithMessage(r => $"'{r.KeyAlgorithm!.Value.ToCanonicalString()}' cannot be a CA key: " +
                r.KeyAlgorithm.Value.GetFamily() switch
                {
                    AlgorithmFamily.Hybrid => "paired issuance is two certificates, not one key.",
                    AlgorithmFamily.Pair => "a signing + encryption pair is two certificates, and one of them is an encryption-only key.",
                    _ => "a key encapsulation key cannot sign."
                });
    }
}
