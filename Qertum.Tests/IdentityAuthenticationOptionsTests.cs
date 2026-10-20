using Microsoft.Extensions.Configuration;
using Qertum.Services.Auth;

namespace Qertum.Tests;

public sealed class IdentityAuthenticationOptionsTests
{
    private static IdentityAuthenticationOptions Bind(Dictionary<string, string?> values)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        var options = new IdentityAuthenticationOptions();
        configuration.GetSection(IdentityAuthenticationOptions.SectionName).Bind(options);
        return options;
    }

    [Fact]
    public void Defaults_AreOpenIddictCompatible()
    {
        var options = new IdentityAuthenticationOptions();

        Assert.Equal("qertum-api", options.Audience);
        Assert.True(options.RequireHttpsMetadata);
        Assert.Equal("preferred_username", options.NameClaimType);
        Assert.Equal("role", options.RoleClaimType);
        Assert.Equal("scope", options.ScopeClaimType);
    }

    [Fact]
    public void Bind_ReadsIdentitySection()
    {
        var options = Bind(new Dictionary<string, string?>
        {
            ["Identity:Authority"] = "https://idp.example",
            ["Identity:Audience"] = "other-api",
            ["Identity:RequireHttpsMetadata"] = "false",
            ["Identity:RoleClaimType"] = "realm_access.roles"
        });

        Assert.Equal("https://idp.example", options.Authority);
        Assert.Equal("other-api", options.Audience);
        Assert.False(options.RequireHttpsMetadata);
        Assert.Equal("realm_access.roles", options.RoleClaimType);
    }

    [Fact]
    public void Validate_ThrowsWhenAuthorityMissing()
    {
        var options = new IdentityAuthenticationOptions();

        var ex = Assert.Throws<InvalidOperationException>(() => options.Validate(isDevelopment: false));

        Assert.Contains("Identity:Authority", ex.Message);
    }

    [Fact]
    public void Validate_ThrowsWhenAuthorityIsNotAbsoluteUrl()
    {
        var options = new IdentityAuthenticationOptions { Authority = "idp.example" };

        var ex = Assert.Throws<InvalidOperationException>(() => options.Validate(isDevelopment: false));

        Assert.Contains("absolute URL", ex.Message);
    }

    [Fact]
    public void Validate_ThrowsWhenAudienceMissing()
    {
        var options = new IdentityAuthenticationOptions
        {
            Authority = "https://idp.example",
            Audience = ""
        };

        var ex = Assert.Throws<InvalidOperationException>(() => options.Validate(isDevelopment: false));

        Assert.Contains("Identity:Audience", ex.Message);
    }

    [Fact]
    public void Validate_AllowsHttpAuthorityInDevelopment()
    {
        var options = new IdentityAuthenticationOptions { Authority = "http://localhost:7099" };

        options.Validate(isDevelopment: true);

        Assert.False(options.RequireHttpsMetadata);
    }

    [Fact]
    public void Validate_ThrowsForHttpAuthorityOutsideDevelopmentWhenHttpsRequired()
    {
        var options = new IdentityAuthenticationOptions { Authority = "http://idp.example" };

        var ex = Assert.Throws<InvalidOperationException>(() => options.Validate(isDevelopment: false));

        Assert.Contains("RequireHttpsMetadata", ex.Message);
    }

    [Fact]
    public void Validate_AllowsHttpAuthorityOutsideDevelopmentWhenExplicitlyOptedOut()
    {
        var options = new IdentityAuthenticationOptions
        {
            Authority = "http://idp.internal",
            RequireHttpsMetadata = false
        };

        options.Validate(isDevelopment: false);

        Assert.False(options.RequireHttpsMetadata);
    }

    [Fact]
    public void Validate_TrimsTrailingSlashFromAuthority()
    {
        var options = new IdentityAuthenticationOptions { Authority = "https://idp.example/" };

        options.Validate(isDevelopment: false);

        Assert.Equal("https://idp.example", options.Authority);
    }
}
