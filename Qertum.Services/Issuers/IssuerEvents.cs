namespace Qertum.Services.Issuers;

/// <summary>Issuer-family webhook events. Every field is in WebhookEventFields' Issuer allowlist; never add key material.</summary>
internal static class IssuerEvents
{
    public static WebhookEvent For(string eventType, Issuer issuer, string performedBy, int? affectedCertificateCount = null) =>
        new(eventType,
            (Guid)issuer.Id,
            issuer.Name,
            PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["issuerId"] = issuer.Id.ToString(),
                ["issuerName"] = issuer.Name,
                ["kind"] = issuer.Kind.ToString(),
                ["status"] = issuer.Status.ToString(),
                ["subjectDn"] = issuer.SubjectDn,
                ["validTo"] = issuer.ValidTo?.ToString("O"),
                ["affectedCertificateCount"] = affectedCertificateCount?.ToString(System.Globalization.CultureInfo.InvariantCulture)
            });
}
