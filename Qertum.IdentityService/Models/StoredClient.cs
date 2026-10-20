namespace Qertum.IdentityService.Models;

public sealed class StoredClient
{
    public string ClientId { get; set; } = string.Empty;

    public string? ClientSecret { get; set; }

    public string DisplayName { get; set; } = string.Empty;

    public string ClientType { get; set; } = "public";

    public string ConsentType { get; set; } = "implicit";

    public List<string> RedirectUris { get; set; } = new();

    public List<string> PostLogoutRedirectUris { get; set; } = new();

    public List<string> Permissions { get; set; } = new();

    /// <summary>
    /// Roles to include in access tokens issued via client_credentials grant for this client.
    /// Useful for machine-to-machine clients that need role-based API access.
    /// </summary>
    public List<string> Roles { get; set; } = new();
}
