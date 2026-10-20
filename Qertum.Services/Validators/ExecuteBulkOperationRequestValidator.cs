using FluentValidation;

namespace Qertum.Services;

/// <summary>Shape check for executing a bulk operation: the confirmation count cannot be negative.</summary>
public sealed class ExecuteBulkOperationRequestValidator : AbstractValidator<ExecuteBulkOperationRequest>
{
    /// <summary>Creates the validator.</summary>
    public ExecuteBulkOperationRequestValidator()
    {
        RuleFor(r => r.ConfirmCount).GreaterThanOrEqualTo(0);
    }
}
