using FluentValidation;

namespace Qertum.Services.Validators;

internal sealed class SaveIssuancePolicyRequestValidator : AbstractValidator<SaveIssuancePolicyRequest>
{
    public SaveIssuancePolicyRequestValidator()
    {
        RuleFor(r => r.Name).NotEmpty().MaximumLength(100);
        RuleFor(r => r.Description).MaximumLength(500).When(r => r.Description is not null);
    }
}
