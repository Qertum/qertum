using FluentValidation;

namespace Qertum.Services.Validators;

internal sealed class CreateEstEnrollmentCredentialRequestValidator : AbstractValidator<CreateEstEnrollmentCredentialRequest>
{
    public CreateEstEnrollmentCredentialRequestValidator()
    {
        RuleFor(r => r.Username).NotEmpty().MaximumLength(200);

        // HTTP Basic over TLS is the entire security model for /simpleenroll — a short or empty
        // password makes that credential brute-forceable regardless of the rate limiter.
        RuleFor(r => r.Password).NotEmpty().MinimumLength(8);

        RuleFor(r => r.Description).MaximumLength(200);
    }
}
