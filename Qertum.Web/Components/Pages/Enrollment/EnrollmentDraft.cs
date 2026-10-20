using System.Text.Json;
using Qertum.Services;

namespace Qertum.Web.Components.Pages.Enrollment;

/// <summary>
/// Every choice the wizard has collected. One instance lives for the page, so moving back never
/// loses input. <see cref="ToCreateRequest"/> builds the same request the old form did.
/// </summary>
public sealed class EnrollmentDraft
{
    public EnrollmentPurpose? Purpose { get; private set; }

    public EnrollmentTemplateSummary? Template { get; private set; }

    public bool ChoseTemplateDirectly { get; private set; }

    public string CommonName { get; set; } = string.Empty;

    public string DnsNames { get; set; } = string.Empty;

    public string IpAddresses { get; set; } = string.Empty;

    public string EmailAddresses { get; set; } = string.Empty;

    public string UserPrincipalNames { get; set; } = string.Empty;

    public string KeyAlgorithm { get; set; } = "RSA";

    public bool PilotPqc { get; set; }

    public int? ValidityDays { get; set; }

    /// <param name="purpose">The purpose card chosen, or null when the template was picked directly.</param>
    public void SelectTemplate(EnrollmentTemplateSummary template, EnrollmentPurpose? purpose, bool classicalRefused)
    {
        if (Template?.TypeKey != template.TypeKey)
        {
            DnsNames = string.Empty;
            IpAddresses = string.Empty;
            EmailAddresses = string.Empty;
            UserPrincipalNames = string.Empty;
        }

        Template = template;
        Purpose = purpose;
        ChoseTemplateDirectly = purpose is null;
        PilotPqc = false;
        KeyAlgorithm = RecommendedAlgorithm(purpose ?? template.Purposes.FirstOrDefault(), classicalRefused);
    }

    public static string RecommendedAlgorithm(EnrollmentPurpose? purpose, bool classicalRefused) =>
        classicalRefused
            ? "ML-DSA-65"
            : purpose is EnrollmentPurpose.WebServer or EnrollmentPurpose.ClientAuthentication
                ? "ECDSA-P256"
                : "RSA";

    public CreateCertificateRequestRequest ToCreateRequest() => new()
    {
        CommonName = CommonName,
        Type = Template?.TypeKey ?? string.Empty,
        PropertiesJson = JsonSerializer.Serialize(new CertificateProperties
        {
            DnsNames = Split(DnsNames),
            IpAddresses = Split(IpAddresses),
            EmailAddresses = Split(EmailAddresses),
            UserPrincipalNames = Split(UserPrincipalNames)
        }),
        KeyAlgorithm = CertificateKeyAlgorithmExtensions.Parse(KeyAlgorithm),
        ValidityDays = ValidityDays
    };

    private static List<string> Split(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? []
            : value.Split(',').Select(x => x.Trim()).Where(x => !string.IsNullOrEmpty(x)).ToList();
}
