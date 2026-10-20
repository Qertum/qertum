using FluentValidation;
using Microsoft.Extensions.Options;
using Qertum.Services.Policies;

namespace Qertum.Services.Validators;

/// <summary>Validates <see cref="CreatePqcExceptionRequest"/>. Template existence is checked by the service.</summary>
public sealed class CreatePqcExceptionRequestValidator : AbstractValidator<CreatePqcExceptionRequest>
{
    /// <summary>Builds the rules against the configured maximum lifetime.</summary>
    public CreatePqcExceptionRequestValidator(IOptions<PqcExceptionOptions> options, TimeProvider? timeProvider = null)
    {
        var clock = timeProvider ?? TimeProvider.System;
        var maxDays = options.Value.MaxDays;

        RuleFor(r => r.TemplateTypeKey).NotEmpty().MaximumLength(50);
        RuleFor(r => r.NamePattern).NotEmpty().MaximumLength(253)
            .Must(p => IssuancePolicyEvaluator.NormalizeDns(p) is { } n
                       && !n.Contains('*') && !n.Contains(' ') && !System.Net.IPAddress.TryParse(n, out _))
            .WithMessage("NamePattern must be a DNS name or DNS suffix; wildcards and IP addresses are not allowed.");
        RuleFor(r => r.Family).IsInEnum();
        RuleFor(r => r.Reason).NotEmpty().MaximumLength(500);
        RuleFor(r => r.ExpiresAtUtc)
            .Must(e => e.Kind != DateTimeKind.Local).WithMessage("ExpiresAtUtc must be UTC.")
            .Must(e => e > clock.GetUtcNow().UtcDateTime).WithMessage("ExpiresAtUtc must be in the future.")
            .Must(e => e <= clock.GetUtcNow().UtcDateTime.AddDays(maxDays))
            .WithMessage($"ExpiresAtUtc may be at most {maxDays} days from now.");
    }
}
