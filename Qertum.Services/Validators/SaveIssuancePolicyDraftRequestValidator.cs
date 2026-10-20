using FluentValidation;
using Qertum.Services.Acme;

namespace Qertum.Services.Validators;

internal sealed class SaveIssuancePolicyDraftRequestValidator : AbstractValidator<SaveIssuancePolicyDraftRequest>
{
    private const int MaxEntries = 100;
    private const int MaxRequesterRoles = 50;

    public SaveIssuancePolicyDraftRequestValidator()
    {
        RuleFor(r => r.AllowedDnsSuffixes)
            .Cascade(CascadeMode.Stop)
            .NotNull()
            .Must(l => l.Count <= MaxEntries).WithMessage($"At most {MaxEntries} DNS suffixes are allowed.");
        RuleForEach(r => r.AllowedDnsSuffixes)
            .Must(BeValidSuffix)
            .WithMessage("'{PropertyValue}' is not a valid DNS suffix. Use a plain domain such as corp.example.com, without wildcards.");

        RuleFor(r => r.AllowedIpRanges)
            .Cascade(CascadeMode.Stop)
            .NotNull()
            .Must(l => l.Count <= MaxEntries).WithMessage($"At most {MaxEntries} IP ranges are allowed.");
        RuleForEach(r => r.AllowedIpRanges)
            .Must(entry => AcmeAddressPolicy.TryParseNetwork(entry, out _))
            .WithMessage("'{PropertyValue}' is not a valid CIDR range or IP address.");

        RuleFor(r => r.AllowedKeyAlgorithms)
            .Cascade(CascadeMode.Stop)
            .NotNull()
            .Must(l => l.Select(a => a?.Trim().ToUpperInvariant()).Distinct().Count() == l.Count)
            .WithMessage("Key algorithms must not repeat.");
        RuleForEach(r => r.AllowedKeyAlgorithms)
            .Must(a => CertificateKeyAlgorithmExtensions.Parse(a?.Trim()) is not null)
            .WithMessage("'{PropertyValue}' is not a supported key algorithm.");

        RuleFor(r => r.AllowedRequesterRoles)
            .Cascade(CascadeMode.Stop)
            .NotNull()
            .Must(l => l.Count <= MaxRequesterRoles).WithMessage($"At most {MaxRequesterRoles} requester roles are allowed.")
            .Must(l => l.Select(r => r?.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).Count() == l.Count)
            .WithMessage("Requester roles must not repeat (names are compared ignoring case).");
        RuleForEach(r => r.AllowedRequesterRoles)
            .Must(r => RoleNameRules.IsValid(r))
            .WithMessage("'{PropertyValue}' is not a valid role name.")
            .Must(r => !string.Equals(r?.Trim(), AppRoles.Admin, StringComparison.OrdinalIgnoreCase))
            .WithMessage("'admin' always passes; listing it has no effect.");

        RuleFor(r => r.MaxValidityDays).GreaterThanOrEqualTo(1).When(r => r.MaxValidityDays.HasValue);
    }

    private static bool BeValidSuffix(string? suffix)
    {
        if (string.IsNullOrWhiteSpace(suffix) || suffix.Contains('*'))
            return false;

        return AcmeEndpointMappings.IsValidDnsIdentifier(suffix.Trim().TrimEnd('.'), out _);
    }
}
