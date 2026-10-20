namespace Qertum.Cli.Auth;

internal sealed class CachedSession
{
    public string AccessToken { get; init; } = string.Empty;
    public string? RefreshToken { get; init; }
    public DateTimeOffset ExpiresAt { get; init; }
    public string IdentityUrl { get; set; } = string.Empty;
    public string ApiUrl { get; set; } = string.Empty;
    public string Username { get; init; } = string.Empty;

    public bool IsExpired => TimeProvider.System.GetUtcNow() >= ExpiresAt;
    public bool IsExpiringSoon => TimeProvider.System.GetUtcNow() >= ExpiresAt.AddMinutes(-5);
}
