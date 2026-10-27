using System.Text.Json.Serialization;
namespace Qertum.Services;

/// <summary>
/// What the CA does when the certificate of one of its own issuers (a root, or an intermediate installed
/// under a parent) is revoked. Either way the issuer stops issuing at once and keeps answering CRL and OCSP
/// for what it signed. Stored and serialized as the name.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum RevokedIssuerMode
{
    /// <summary>
    /// The revoked issuer and every issuer below it are retired. With no issuer left that can sign, the CA
    /// reports itself not initialized and onboarding creates a new root from scratch.
    /// </summary>
    HardStop,

    /// <summary>
    /// Only the revoked issuer is retired and stops being the default. Another active issuer can be made
    /// default; the rest of the hierarchy is left as it is.
    /// </summary>
    Retire
}
