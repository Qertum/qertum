using System.Text.Json;
using Qertum.Services.Policies;

namespace Qertum.Services.Enrollment;

/// <summary>
/// Derives the purposes a template serves from its key usages and EKUs. Pure: no database, never
/// throws. <c>KeyCertSign</c> makes a template a subordinate CA and nothing else, so a CA-capable
/// template is never offered as a web server or client certificate — the same signal
/// the generator uses for <c>BasicConstraints CA:TRUE</c> (<c>CaCapableTemplate</c>).
/// </summary>
public static class EnrollmentPurposeClassifier
{
    private const string ServerAuth = "1.3.6.1.5.5.7.3.1";
    private const string ClientAuth = "1.3.6.1.5.5.7.3.2";
    private const string CodeSigning = "1.3.6.1.5.5.7.3.3";
    private const string EmailProtection = "1.3.6.1.5.5.7.3.4";

    public static IReadOnlyList<EnrollmentPurpose> Classify(string? keyUsagesJson, string? extendedKeyUsagesJson)
    {
        if (CaCapableTemplate.IsCaCapable(keyUsagesJson))
            return [EnrollmentPurpose.SubordinateCa];

        var ekus = ParseStringArray(extendedKeyUsagesJson);
        var purposes = new List<EnrollmentPurpose>();
        if (ekus.Contains(ServerAuth)) purposes.Add(EnrollmentPurpose.WebServer);
        if (ekus.Contains(ClientAuth)) purposes.Add(EnrollmentPurpose.ClientAuthentication);
        if (ekus.Contains(EmailProtection)) purposes.Add(EnrollmentPurpose.Email);
        if (ekus.Contains(CodeSigning)) purposes.Add(EnrollmentPurpose.CodeSigning);

        return purposes.Count == 0 ? [EnrollmentPurpose.Other] : purposes;
    }

    /// <summary>Parses a JSON array of strings; anything else (null, blank, malformed) is empty.</summary>
    public static IReadOnlyList<string> ParseStringArray(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return [];

        try
        {
            return (JsonSerializer.Deserialize<List<string?>>(json) ?? [])
                .Where(value => !string.IsNullOrEmpty(value))
                .Select(value => value!)
                .ToList();
        }
        catch (JsonException)
        {
            return [];
        }
    }
}
