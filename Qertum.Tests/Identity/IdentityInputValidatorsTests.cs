using Qertum.IdentityService.Pages;
using Qertum.IdentityService.Pages.Account;
using Qertum.IdentityService.Validators;
using NewUserInput = Qertum.IdentityService.Pages.Admin.Users.NewModel.InputModel;

namespace Qertum.Tests.Identity;

/// <summary>
/// The IdentityService validates page input with FluentValidation, the same method Qertum.Services
/// uses, instead of DataAnnotations attributes. These pin the rules the attributes used to carry.
/// </summary>
public sealed class IdentityInputValidatorsTests
{
    [Fact]
    public void Login_RequiresUsernameAndPassword()
    {
        var validator = new LoginInputValidator();

        Assert.False(validator.Validate(new LoginModel.InputModel()).IsValid);
        Assert.True(validator.Validate(new LoginModel.InputModel { Username = "alice", Password = "x" }).IsValid);
    }

    [Fact]
    public void Profile_RequiresADisplayNameAndAcceptsAnEmptyEmail()
    {
        var validator = new ProfileInputValidator();

        Assert.False(validator.Validate(new IndexModel.InputModel { DisplayName = null }).IsValid);
        Assert.False(validator.Validate(new IndexModel.InputModel { DisplayName = new string('a', 101) }).IsValid);
        Assert.False(validator.Validate(new IndexModel.InputModel { DisplayName = "Alice", Email = "not-an-email" }).IsValid);
        Assert.True(validator.Validate(new IndexModel.InputModel { DisplayName = "Alice", Email = null }).IsValid);
    }

    [Theory]
    [InlineData("short")]
    [InlineData(null)]
    public void ChangePassword_RefusesANewPasswordUnderEightCharacters(string? newPassword)
    {
        var result = new ChangePasswordInputValidator().Validate(new ChangePasswordModel.InputModel
        {
            CurrentPassword = "old-password", NewPassword = newPassword, ConfirmPassword = newPassword
        });

        Assert.False(result.IsValid);
        if (newPassword is not null)
            Assert.Contains(result.Errors, e => e.ErrorMessage == "Password must be at least 8 characters.");
    }

    [Fact]
    public void NewUser_RequiresUsernameAndAValidEmailWithinTheirLengths()
    {
        var validator = new NewUserInputValidator();

        Assert.False(validator.Validate(new NewUserInput { Username = "bob" }).IsValid);
        Assert.False(validator.Validate(new NewUserInput { Username = new string('b', 65), Email = "bob@example.com" }).IsValid);
        Assert.True(validator.Validate(new NewUserInput { Username = "bob", Email = "bob@example.com" }).IsValid);
    }
}
