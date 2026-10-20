namespace Qertum.Web.Auth;

/// <summary>The <c>OpenIdConnect</c> section.</summary>
public sealed class OidcMetadataOptions
{
    public const string SectionName = "OpenIdConnect";

    /// <summary>
    /// Fetch the identity provider's metadata over HTTPS only. Development always allows HTTP; turn this
    /// off only for a deployment that reaches the identity authority over plain HTTP, such as the
    /// single-container image.
    /// </summary>
    public bool RequireHttpsMetadata { get; set; } = true;
}
