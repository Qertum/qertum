using Microsoft.Extensions.Configuration;
using Qertum.IdentityService.Configuration;

namespace Qertum.Tests;

public sealed class IdentityServiceOptionsTests
{
    private static IdentityServiceOptions Bind(Dictionary<string, string?> values)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        var options = new IdentityServiceOptions();
        configuration.GetSection(IdentityServiceOptions.SectionName).Bind(options);
        return options;
    }

    private static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"idp-opts-{Guid.NewGuid():N}");
        return dir;
    }

    [Fact]
    public void Bind_ReadsIdentityServiceSection()
    {
        var options = Bind(new Dictionary<string, string?>
        {
            ["IdentityService:Authority"] = "https://idp.example",
            ["IdentityService:DataPath"] = "/data",
            ["IdentityService:DisableTransportSecurity"] = "true",
            ["IdentityService:EnableServiceDiscoveryRedirectUris"] = "true",
            ["IdentityService:ApiClientSecret"] = "s3cret"
        });

        Assert.Equal("https://idp.example", options.Authority);
        Assert.Equal("/data", options.DataPath);
        Assert.True(options.DisableTransportSecurity);
        Assert.True(options.EnableServiceDiscoveryRedirectUris);
        Assert.Equal("s3cret", options.ApiClientSecret);
    }

    [Fact]
    public void Validate_ThrowsWhenAuthorityMissingOutsideDevelopment()
    {
        var options = new IdentityServiceOptions();

        var ex = Assert.Throws<InvalidOperationException>(() => options.Validate(isDevelopment: false));

        Assert.Contains("IdentityService:Authority", ex.Message);
    }

    [Fact]
    public void Validate_AllowsMissingAuthorityInDevelopment()
    {
        var options = new IdentityServiceOptions();

        options.Validate(isDevelopment: true);

        Assert.Equal(string.Empty, options.Authority);
    }

    [Fact]
    public void Validate_ThrowsWhenAuthorityIsNotAbsoluteUrl()
    {
        var options = new IdentityServiceOptions { Authority = "idp.example" };

        var ex = Assert.Throws<InvalidOperationException>(() => options.Validate(isDevelopment: false));

        Assert.Contains("absolute URL", ex.Message);
    }

    [Theory]
    [InlineData("ftp://idp.example")]
    [InlineData("file:///etc/idp")]
    public void Validate_ThrowsWhenAuthorityUsesANonHttpScheme(string authority)
    {
        var options = new IdentityServiceOptions { Authority = authority };

        var ex = Assert.Throws<InvalidOperationException>(() => options.Validate(isDevelopment: false));

        Assert.Contains("http or https", ex.Message);
    }

    [Fact]
    public void Validate_AllowsPlainHttpAuthority()
    {
        // deploy/identity/docker-compose.yml ships http://localhost:8081 — TLS is expected to
        // terminate at a proxy, so unlike the consumer-side Identity:Authority there is no
        // "HTTPS outside Development" rule here.
        var options = new IdentityServiceOptions { Authority = "http://localhost:8081" };

        options.Validate(isDevelopment: false);

        Assert.Equal("http://localhost:8081", options.Authority);
    }

    [Fact]
    public void Validate_TrimsTrailingSlashFromAuthority()
    {
        var options = new IdentityServiceOptions { Authority = "https://idp.example/" };

        options.Validate(isDevelopment: false);

        Assert.Equal("https://idp.example", options.Authority);
    }

    [Fact]
    public void Validate_DefaultsServiceDiscoveryToDevelopmentOnly()
    {
        var production = new IdentityServiceOptions { Authority = "https://idp.example" };
        production.Validate(isDevelopment: false);
        Assert.False(production.ServiceDiscoveryRedirectUrisEnabled);

        var development = new IdentityServiceOptions();
        development.Validate(isDevelopment: true);
        Assert.True(development.ServiceDiscoveryRedirectUrisEnabled);
    }

    [Fact]
    public void Validate_HonoursExplicitServiceDiscoveryFlagOutsideDevelopment()
    {
        var options = new IdentityServiceOptions
        {
            Authority = "https://idp.example",
            EnableServiceDiscoveryRedirectUris = true
        };

        options.Validate(isDevelopment: false);

        Assert.True(options.ServiceDiscoveryRedirectUrisEnabled);
    }

    [Fact]
    public void ResolveDataPath_CreatesConfiguredDirectory()
    {
        var dir = TempDir();
        var options = new IdentityServiceOptions
        {
            Authority = "https://idp.example",
            DataPath = dir
        };
        options.Validate(isDevelopment: false);

        var resolved = options.ResolveDataPath();

        Assert.Equal(Path.GetFullPath(dir), resolved);
        Assert.True(Directory.Exists(resolved));

        Directory.Delete(resolved, recursive: true);
    }

    [Fact]
    public void ResolveDataPath_FallsBackToBaseDirectoryWhenUnset()
    {
        var options = new IdentityServiceOptions { Authority = "https://idp.example" };
        options.Validate(isDevelopment: false);

        Assert.Equal(
            Path.GetFullPath(AppContext.BaseDirectory),
            options.ResolveDataPath());
    }

    [Fact]
    public void ResolveDataPath_ReturnsAbsolutePathForRelativeConfiguration()
    {
        var relative = Path.Combine("idp-relative", Guid.NewGuid().ToString("N"));
        var options = new IdentityServiceOptions
        {
            Authority = "https://idp.example",
            DataPath = relative
        };
        options.Validate(isDevelopment: false);

        var resolved = options.ResolveDataPath();

        Assert.True(Path.IsPathRooted(resolved));
        Assert.True(Directory.Exists(resolved));

        Directory.Delete(resolved, recursive: true);
    }
}
