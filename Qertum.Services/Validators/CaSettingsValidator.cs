using System.Text.Json;
using FluentValidation;
using Qertum.Services.Acme;

namespace Qertum.Services.Validators;

internal sealed class CaSettingsValidator : AbstractValidator<CaSettings>
{
    public CaSettingsValidator()
    {
        RuleFor(s => s.OrganizationName)
            .MaximumLength(200)
            .Must(v => !CertificateRequestValidator.ContainsInvalidDnChars(v))
            .WithMessage("OrganizationName contains invalid X.500 characters.")
            .When(s => s.OrganizationName is not null);

        RuleFor(s => s.OrganizationalUnit)
            .MaximumLength(200)
            .Must(v => !CertificateRequestValidator.ContainsInvalidDnChars(v))
            .WithMessage("OrganizationalUnit contains invalid X.500 characters.")
            .When(s => s.OrganizationalUnit is not null);

        RuleFor(s => s.State)
            .MaximumLength(200)
            .Must(v => !CertificateRequestValidator.ContainsInvalidDnChars(v))
            .WithMessage("State contains invalid X.500 characters.")
            .When(s => s.State is not null);

        RuleFor(s => s.Locality)
            .MaximumLength(200)
            .Must(v => !CertificateRequestValidator.ContainsInvalidDnChars(v))
            .WithMessage("Locality contains invalid X.500 characters.")
            .When(s => s.Locality is not null);

        RuleFor(s => s.Country)
            .MaximumLength(2)
            .Must(c => CertificateRequestValidator.ValidCountryCodes.Contains(c!))
            .WithMessage("Country must be a valid ISO 3166-1 alpha-2 code.")
            .When(s => !string.IsNullOrWhiteSpace(s.Country));

        RuleFor(s => s.CrlDistributionPoint)
            .MaximumLength(2000)
            .Must(url => Uri.TryCreate(url, UriKind.Absolute, out _))
            .WithMessage("CrlDistributionPoint must be a valid absolute URL.")
            .When(s => !string.IsNullOrWhiteSpace(s.CrlDistributionPoint));

        RuleFor(s => s.OcspResponderUrl)
            .MaximumLength(2000)
            .Must(url => Uri.TryCreate(url, UriKind.Absolute, out _))
            .WithMessage("OcspResponderUrl must be a valid absolute URL.")
            .When(s => !string.IsNullOrWhiteSpace(s.OcspResponderUrl));

        RuleFor(s => s.PublicBaseUrl)
            .MaximumLength(2000)
            .Must(url => Uri.TryCreate(url, UriKind.Absolute, out var uri)
                         && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps)
                         && string.IsNullOrEmpty(uri.Query) && string.IsNullOrEmpty(uri.Fragment))
            .WithMessage("PublicBaseUrl must be an absolute http(s) URL without query or fragment.")
            .When(s => !string.IsNullOrWhiteSpace(s.PublicBaseUrl));

        RuleFor(s => s.CrlDeltaDistributionPoint)
            .MaximumLength(2000)
            .Must(url => Uri.TryCreate(url, UriKind.Absolute, out _))
            .WithMessage("CrlDeltaDistributionPoint must be a valid absolute URL.")
            .When(s => !string.IsNullOrWhiteSpace(s.CrlDeltaDistributionPoint));

        RuleFor(s => s.ExpiringSoonDays).GreaterThan(0);
        RuleFor(s => s.CertificateValidityDays).GreaterThan(0);
        RuleFor(s => s.CrlValidityHours).GreaterThan(0);
        RuleFor(s => s.DeltaCrlValidityHours).GreaterThan(0);
        RuleFor(s => s.AttentionPendingApprovalAgeHours).GreaterThan(0);
        RuleFor(s => s.AttentionFailureLookbackDays).GreaterThan(0);
        RuleFor(s => s.AttentionBackupMaxAgeHours).GreaterThan(0);
        RuleFor(s => s.AttentionRestoreVerifiedMaxAgeDays).GreaterThan(0);

        RuleFor(s => s.AcmeChallengeAllowedNetworksJson)
            .MaximumLength(4000)
            .Custom(ValidateAllowedNetworks);
    }

    /// <summary>
    /// The allowlist is stored as a JSON array of CIDR strings. Rejecting malformed entries here is
    /// what keeps <see cref="Acme.AcmeAddressPolicy"/> from having to ignore them at connect time.
    /// </summary>
    private static void ValidateAllowedNetworks(string? json, ValidationContext<CaSettings> context)
    {
        if (string.IsNullOrWhiteSpace(json))
            return;

        List<string>? entries;
        try
        {
            entries = JsonSerializer.Deserialize<List<string>>(json);
        }
        catch (JsonException)
        {
            context.AddFailure("AcmeChallengeAllowedNetworksJson must be a JSON array of CIDR strings.");
            return;
        }

        if (entries is null)
            return;

        if (entries.Count > AcmeAddressPolicy.MaxEntries)
        {
            context.AddFailure(
                $"At most {AcmeAddressPolicy.MaxEntries} allowed networks may be configured.");
            return;
        }

        foreach (var entry in entries)
        {
            if (!AcmeAddressPolicy.TryParseNetwork(entry, out _))
                context.AddFailure($"'{entry}' is not a valid CIDR range or IP address.");
        }
    }
}
