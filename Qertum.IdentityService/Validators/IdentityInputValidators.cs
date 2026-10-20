using FluentValidation;
using Qertum.IdentityService.Pages;
using Qertum.IdentityService.Pages.Account;
using NewUserInput = Qertum.IdentityService.Pages.Admin.Users.NewModel.InputModel;

namespace Qertum.IdentityService.Validators;

// Page input is validated with FluentValidation, the method Qertum.Services uses, rather than
// DataAnnotations attributes. The IdentityService stays independent: it references the FluentValidation
// package, never Qertum.Services. Registered as singletons in Program.cs.

public sealed class LoginInputValidator : AbstractValidator<LoginModel.InputModel>
{
    public LoginInputValidator()
    {
        RuleFor(x => x.Username).NotEmpty();
        RuleFor(x => x.Password).NotEmpty();
    }
}

public sealed class ProfileInputValidator : AbstractValidator<IndexModel.InputModel>
{
    public ProfileInputValidator()
    {
        RuleFor(x => x.DisplayName).NotEmpty().MaximumLength(100);
        RuleFor(x => x.Email).EmailAddress().MaximumLength(200);
    }
}

public sealed class ChangePasswordInputValidator : AbstractValidator<ChangePasswordModel.InputModel>
{
    public ChangePasswordInputValidator()
    {
        RuleFor(x => x.CurrentPassword).NotEmpty();
        RuleFor(x => x.NewPassword).NotEmpty().Length(8, 200).WithMessage("Password must be at least 8 characters.");
        RuleFor(x => x.ConfirmPassword).NotEmpty();
    }
}

public sealed class NewUserInputValidator : AbstractValidator<NewUserInput>
{
    public NewUserInputValidator()
    {
        RuleFor(x => x.Username).NotEmpty().MaximumLength(64);
        RuleFor(x => x.DisplayName).MaximumLength(100);
        RuleFor(x => x.Email).NotEmpty().EmailAddress().MaximumLength(200);
    }
}
