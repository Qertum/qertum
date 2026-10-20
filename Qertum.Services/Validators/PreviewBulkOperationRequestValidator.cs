using FluentValidation;

namespace Qertum.Services;

/// <summary>Shape checks for a bulk preview. The service enforces the rules that need data (eligibility, cap).</summary>
public sealed class PreviewBulkOperationRequestValidator : AbstractValidator<PreviewBulkOperationRequest>
{
    /// <summary>Creates the validator.</summary>
    public PreviewBulkOperationRequestValidator()
    {
        RuleFor(r => r.Kind).IsInEnum();
        RuleFor(r => r.Filter).NotNull();
        RuleFor(r => r.Reason).MaximumLength(500);
        RuleFor(r => r.Filter.TemplateKey).MaximumLength(100).When(r => r.Filter is not null);
        RuleFor(r => r.Filter.OwnerSubject).MaximumLength(200).When(r => r.Filter is not null);
        RuleFor(r => r.Filter.CommonNameContains).MaximumLength(200).When(r => r.Filter is not null);
        RuleFor(r => r.Filter.ExpiresWithinDays).InclusiveBetween(0, 36500).When(r => r.Filter?.ExpiresWithinDays is not null);
    }
}
