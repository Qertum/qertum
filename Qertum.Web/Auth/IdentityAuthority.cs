namespace Qertum.Web.Auth;

public sealed class IdentityAuthority
{
    public string Url { get; }

    public IdentityAuthority(IConfiguration configuration)
    {
        Url = configuration.ResolveIdentityServiceAuthority();
    }

    public string AccountUrl => $"{Url.TrimEnd('/')}/Account";
    public string ChangePasswordUrl => $"{Url.TrimEnd('/')}/Account/ChangePassword";
    public string LogoutUrl => $"{Url.TrimEnd('/')}/Account/Logout";
}
