using FluentValidation;

namespace Qertum.Services.Validators;

/// <summary>Same validity bounds as creating an intermediate; null keeps the old one's length.</summary>
internal sealed class RenewIssuerRequestValidator : AbstractValidator<RenewIssuerRequest>
{
    public RenewIssuerRequestValidator()
    {
        RuleFor(r => r.ValidityDays).InclusiveBetween(1, 36500).When(r => r.ValidityDays is not null);
    }
}
