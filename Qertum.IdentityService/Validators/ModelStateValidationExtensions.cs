using FluentValidation.Results;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Qertum.IdentityService.Validators;

public static class ModelStateValidationExtensions
{
    /// <summary>
    /// Copies validation failures into ModelState under the bound property's key (<c>Input.Email</c>),
    /// which is what <c>asp-validation-for</c> and <c>ModelState.IsValid</c> read.
    /// </summary>
    public static void AddValidationErrors(this ModelStateDictionary modelState, ValidationResult result, string prefix = "Input")
    {
        foreach (var error in result.Errors)
            modelState.AddModelError($"{prefix}.{error.PropertyName}", error.ErrorMessage);
    }
}
