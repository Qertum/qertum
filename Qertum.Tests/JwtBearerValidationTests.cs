using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Qertum.Services.Auth;

namespace Qertum.Tests;

/// <summary>
/// Validates token acceptance and rejection against the real TokenValidationParameters
/// produced by AddQertumJwtAuthentication, using a locally generated signing key so the
/// tests need no live identity provider.
/// </summary>
public sealed class JwtBearerValidationTests : IDisposable
{
    private const string Authority = "https://idp.example";
    private const string Audience = "qertum-api";

    private readonly RSA _rsa = RSA.Create(2048);
    private readonly ServiceProvider _provider;

    public JwtBearerValidationTests()
    {
        var configuration = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Identity:Authority"] = Authority,
                ["Identity:Audience"] = Audience
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddQertumJwtAuthentication(configuration, isDevelopment: false);
        _provider = services.BuildServiceProvider();
    }

    public void Dispose()
    {
        _provider.Dispose();
        _rsa.Dispose();
    }

    private TokenValidationParameters GetParameters()
    {
        var monitor = _provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>();
        var parameters = monitor.Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters.Clone();

        // Supply the signing key directly instead of fetching JWKS from a live issuer.
        parameters.IssuerSigningKey = new RsaSecurityKey(_rsa) { KeyId = "test-key" };
        parameters.ConfigurationManager = null;
        return parameters;
    }

    /// <summary>
    /// Returns the actual token handler configured by AddQertumJwtAuthentication (i.e.
    /// options.TokenHandlers[0]) rather than a freshly constructed JsonWebTokenHandler.
    /// A fresh handler defaults MapInboundClaims to false on its own, which would silently
    /// exercise a different configuration than production and never notice a regression to
    /// jwt.MapInboundClaims in AuthenticationServiceCollectionExtensions.
    /// </summary>
    private TokenHandler GetHandler()
    {
        var monitor = _provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>();
        var options = monitor.Get(JwtBearerDefaults.AuthenticationScheme);
        return options.TokenHandlers[0];
    }

    private string CreateToken(
        string issuer = Authority,
        string audience = Audience,
        int expiresInMinutes = 10,
        params Claim[] extraClaims)
    {
        var claims = new List<Claim> { new("sub", "user-1"), new("role", "admin") };
        claims.AddRange(extraClaims);

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Subject = new ClaimsIdentity(claims),
            // Explicit NotBefore, always well before Expires. JsonWebTokenHandler.CreateToken
            // defaults an omitted NotBefore to DateTime.UtcNow; for the expired-token case that
            // would put "nbf" after "exp" and make the library report
            // SecurityTokenInvalidLifetimeException ("nbf after exp") instead of the intended
            // SecurityTokenExpiredException for a token that was valid and has since expired.
            NotBefore = DateTime.UtcNow.AddMinutes(Math.Min(expiresInMinutes, 0) - 60),
            Expires = DateTime.UtcNow.AddMinutes(expiresInMinutes),
            SigningCredentials = new SigningCredentials(
                new RsaSecurityKey(_rsa) { KeyId = "test-key" },
                SecurityAlgorithms.RsaSha256)
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    [Fact]
    public async Task ValidToken_IsAccepted()
    {
        var result = await GetHandler()
            .ValidateTokenAsync(CreateToken(), GetParameters());

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task TokenWithWrongAudience_IsRejected()
    {
        var result = await GetHandler()
            .ValidateTokenAsync(CreateToken(audience: "some-other-api"), GetParameters());

        Assert.False(result.IsValid);
        Assert.IsType<SecurityTokenInvalidAudienceException>(result.Exception);
    }

    [Fact]
    public async Task TokenWithWrongIssuer_IsRejected()
    {
        var result = await GetHandler()
            .ValidateTokenAsync(CreateToken(issuer: "https://attacker.example"), GetParameters());

        Assert.False(result.IsValid);
        Assert.IsType<SecurityTokenInvalidIssuerException>(result.Exception);
    }

    [Fact]
    public async Task ExpiredToken_IsRejected()
    {
        var result = await GetHandler()
            .ValidateTokenAsync(CreateToken(expiresInMinutes: -60), GetParameters());

        Assert.False(result.IsValid);
        Assert.IsType<SecurityTokenExpiredException>(result.Exception);
    }

    [Fact]
    public async Task TokenSignedByUnknownKey_IsRejected()
    {
        using var otherKey = RSA.Create(2048);
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = Authority,
            Audience = Audience,
            Subject = new ClaimsIdentity([new Claim("sub", "user-1")]),
            Expires = DateTime.UtcNow.AddMinutes(10),
            SigningCredentials = new SigningCredentials(
                new RsaSecurityKey(otherKey) { KeyId = "other-key" },
                SecurityAlgorithms.RsaSha256)
        };
        var token = new JsonWebTokenHandler().CreateToken(descriptor);

        var result = await GetHandler().ValidateTokenAsync(token, GetParameters());

        Assert.False(result.IsValid);
        Assert.IsType<SecurityTokenSignatureKeyNotFoundException>(result.Exception);
    }

    [Fact]
    public async Task ValidatedPrincipal_ExposesRolesToTheClaimsMapper()
    {
        var result = await GetHandler()
            .ValidateTokenAsync(CreateToken(), GetParameters());

        Assert.True(result.IsValid);

        var principal = new ClaimsPrincipal(result.ClaimsIdentity);
        var mapper = _provider.GetRequiredService<IIdentityClaimsMapper>();

        Assert.True(mapper.IsAdmin(principal));
    }

    [Fact]
    public async Task ValidatedPrincipal_KeepsWireClaimTypesUnmapped()
    {
        // Pins jwt.MapInboundClaims = false end-to-end. If that production setting were
        // dropped (or a fresh handler bypassed it), the token handler would translate "sub"
        // to the legacy ClaimTypes.NameIdentifier URI and audit attribution
        // (IdentityClaimsMapper.GetName / GetPerformedBy) would silently degrade.
        var result = await GetHandler()
            .ValidateTokenAsync(CreateToken(), GetParameters());

        Assert.True(result.IsValid);

        var principal = new ClaimsPrincipal(result.ClaimsIdentity);

        Assert.Equal("user-1", principal.FindFirst("sub")?.Value);
        Assert.Null(principal.FindFirst(ClaimTypes.NameIdentifier));
    }
}
