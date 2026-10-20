using System.Buffers;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Qertum.Services;

/// <summary>
/// Centralized validation rules for certificate DN fields, DNS names, and template type keys.
/// Referenced by both the API endpoint layer and any future service-layer callers.
/// </summary>
public static partial class CertificateRequestValidator
{
    private static readonly SearchValues<char> InvalidDnChars =
        SearchValues.Create([',', '=', '+', '"', '\\', '<', '>', ';']);

    [GeneratedRegex("^[A-Za-z][A-Za-z0-9_-]{0,49}$")]
    private static partial Regex TypeKeyPattern();

    /// <summary>ISO 3166-1 alpha-2 country codes accepted in DN Country fields.</summary>
    public static readonly IReadOnlySet<string> ValidCountryCodes =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "AF","AX","AL","DZ","AS","AD","AO","AI","AQ","AG","AR","AM","AW","AU","AT","AZ","BS","BH","BD","BB","BY","BE",
            "BZ","BJ","BM","BT","BO","BQ","BA","BW","BV","BR","IO","BN","BG","BF","BI","CV","KH","CM","CA","KY","CF","TD",
            "CL","CN","CX","CC","CO","KM","CG","CD","CK","CR","CI","HR","CU","CW","CY","CZ","DK","DJ","DM","DO","EC","EG",
            "SV","GQ","ER","EE","SZ","ET","FK","FO","FJ","FI","FR","GF","PF","TF","GA","GM","GE","DE","GH","GI","GR","GL",
            "GD","GP","GU","GT","GG","GN","GW","GY","HT","HM","VA","HN","HK","HU","IS","IN","ID","IR","IQ","IE","IM","IL",
            "IT","JM","JP","JE","JO","KZ","KE","KI","KP","KR","KW","KG","LA","LV","LB","LS","LR","LY","LI","LT","LU","MO",
            "MG","MW","MY","MV","ML","MT","MH","MQ","MR","MU","YT","MX","FM","MD","MC","MN","ME","MS","MA","MZ","MM","NA",
            "NR","NP","NL","NC","NZ","NI","NE","NG","NU","NF","MK","MP","NO","OM","PK","PW","PS","PA","PG","PY","PE","PH",
            "PN","PL","PT","PR","QA","RE","RO","RU","RW","BL","SH","KN","LC","MF","PM","VC","WS","SM","ST","SA","SN","RS",
            "SC","SL","SG","SX","SK","SI","SB","SO","ZA","GS","SS","ES","LK","SD","SR","SJ","SE","CH","SY","TW","TJ","TZ",
            "TH","TL","TG","TK","TO","TT","TN","TR","TM","TC","TV","UG","UA","AE","GB","US","UM","UY","UZ","VU","VE","VN",
            "VG","VI","WF","EH","YE","ZM","ZW"
        };

    /// <summary>Returns true if the value contains X.500 metacharacters that would break DN parsing.</summary>
    public static bool ContainsInvalidDnChars(string? value) =>
        !string.IsNullOrEmpty(value) && value.IndexOfAny(InvalidDnChars) >= 0;

    /// <summary>Validates the JSON-encoded certificate properties (SANs etc.).</summary>
    public static bool ValidatePropertiesJson(string propertiesJson, out string? errorMessage)
    {
        errorMessage = null;
        if (string.IsNullOrWhiteSpace(propertiesJson)) return true;

        try
        {
            var props = JsonSerializer.Deserialize<CertificateProperties>(propertiesJson, AppJsonOptions.Default);
            var invalidDns = props?.DnsNames?.FirstOrDefault(dns => !IsValidDnsName(dns));
            if (invalidDns != null)
            {
                errorMessage = $"Invalid SAN DNS name: {invalidDns}";
                return false;
            }
        }
        catch
        {
            errorMessage = "Invalid JSON in properties.";
            return false;
        }

        return true;
    }

    /// <summary>Validates a certificate template TypeKey against its naming rules.</summary>
    public static bool IsValidTypeKey(string typeKey, out string? errorMessage)
    {
        errorMessage = null;
        if (string.IsNullOrWhiteSpace(typeKey))
        {
            errorMessage = "TypeKey cannot be empty.";
            return false;
        }
        if (TypeKeyPattern().IsMatch(typeKey)) return true;

        errorMessage = "TypeKey must start with a letter and contain only letters, digits, hyphens, or underscores (max 50 chars).";
        return false;
    }

    /// <summary>Returns true if the name is a syntactically valid DNS hostname (wildcards allowed).</summary>
    private static bool IsValidDnsName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        if (name.StartsWith("*.")) name = name[2..];
        return Uri.CheckHostName(name) == UriHostNameType.Dns;
    }
}
