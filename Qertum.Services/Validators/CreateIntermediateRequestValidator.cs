using FluentValidation;
using Qertum.Services.Acme;
using Qertum.Services.Policies;

namespace Qertum.Services.Validators;

internal sealed class CreateIntermediateRequestValidator : AbstractValidator<CreateIntermediateRequest>
{
    public CreateIntermediateRequestValidator()
    {
        RuleFor(r => r.Name).NotEmpty().MaximumLength(200);
        RuleFor(r => r.CommonName).NotEmpty().MaximumLength(200);
        RuleFor(r => r.OrganizationName).MaximumLength(200);
        RuleFor(r => r.OrganizationalUnit).MaximumLength(200);
        RuleFor(r => r.State).MaximumLength(200);
        RuleFor(r => r.Locality).MaximumLength(200);
        RuleFor(r => r.Country)
            .Must(c => CertificateRequestValidator.ValidCountryCodes.Contains(c!))
            .WithMessage("Country must be a valid ISO 3166-1 alpha-2 code.")
            .When(r => !string.IsNullOrWhiteSpace(r.Country));
        RuleFor(r => r.ValidityDays).InclusiveBetween(1, 36500);
        RuleFor(r => r.PathLength).InclusiveBetween(0, 10).When(r => r.PathLength is not null);
        RuleFor(r => r.KeyAlgorithm)
            .Must(a => a is null || (a.Value.CanSign() && a.Value.GetFamily() != AlgorithmFamily.Hybrid))
            .WithMessage(r => $"'{r.KeyAlgorithm!.Value.ToCanonicalString()}' cannot be a CA key.");

        DnsList(r => r.PermittedDnsSuffixes, nameof(CreateIntermediateRequest.PermittedDnsSuffixes));
        DnsList(r => r.ExcludedDnsSuffixes, nameof(CreateIntermediateRequest.ExcludedDnsSuffixes));
        IpList(r => r.PermittedIpRanges, nameof(CreateIntermediateRequest.PermittedIpRanges));
        IpList(r => r.ExcludedIpRanges, nameof(CreateIntermediateRequest.ExcludedIpRanges));
    }

    private void DnsList(System.Linq.Expressions.Expression<Func<CreateIntermediateRequest, IEnumerable<string>>> list, string label)
    {
        RuleFor(list).Must(l => l.Count() <= 50).WithMessage($"{label} may hold at most 50 entries.");
        RuleForEach(list)
            .Must(v => IssuancePolicyEvaluator.NormalizeDns(v) is { } n && !n.Contains('*') && !n.Contains("..") && !n.StartsWith('.'))
            .WithMessage($"{label}: '{{PropertyValue}}' is not a DNS domain (no wildcards).");
    }

    private void IpList(System.Linq.Expressions.Expression<Func<CreateIntermediateRequest, IEnumerable<string>>> list, string label)
    {
        RuleFor(list).Must(l => l.Count() <= 50).WithMessage($"{label} may hold at most 50 entries.");
        RuleForEach(list)
            .Must(v => System.Net.IPNetwork.TryParse(v, out _))
            .WithMessage($"{label}: '{{PropertyValue}}' is not a CIDR range such as 10.0.0.0/8.");
    }
}
