using System.Security.Claims;
using Qertum.Services;
using Qertum.Services.Auth;

namespace Qertum.Tests;

public sealed class IdentityClaimsMapperTests
{
    private static IdentityClaimsMapper CreateMapper(
        string roleClaimType = "role",
        string scopeClaimType = "scope",
        string nameClaimType = "preferred_username")
    {
        var options = new IdentityAuthenticationOptions
        {
            Authority = "https://idp.example",
            RoleClaimType = roleClaimType,
            ScopeClaimType = scopeClaimType,
            NameClaimType = nameClaimType
        };
        return new IdentityClaimsMapper(options);
    }

    private static ClaimsPrincipal PrincipalWith(params Claim[] claims) =>
        new(new ClaimsIdentity(claims, authenticationType: "Bearer"));

    [Fact]
    public void GetRoles_ReadsRepeatedClaims_OpenIddictShape()
    {
        var mapper = CreateMapper(roleClaimType: "role");
        var principal = PrincipalWith(new Claim("role", "admin"), new Claim("role", "viewer"));

        var roles = mapper.GetRoles(principal);

        Assert.Equal(["admin", "viewer"], roles.OrderBy(r => r).ToArray());
    }

    [Fact]
    public void GetRoles_ReadsRepeatedClaims_EntraShape()
    {
        var mapper = CreateMapper(roleClaimType: "roles");
        var principal = PrincipalWith(new Claim("roles", "certificate-operator"));

        var roles = mapper.GetRoles(principal);

        Assert.Equal(["certificate-operator"], roles.ToArray());
    }

    [Fact]
    public void GetRoles_ReadsNestedJsonClaim_KeycloakShape()
    {
        var mapper = CreateMapper(roleClaimType: "realm_access.roles");
        var principal = PrincipalWith(
            new Claim("realm_access", """{"roles":["admin","viewer"]}""", "JSON"));

        var roles = mapper.GetRoles(principal);

        Assert.Equal(["admin", "viewer"], roles.OrderBy(r => r).ToArray());
    }

    [Fact]
    public void GetRoles_FallsBackToStandardRoleClaimType()
    {
        var mapper = CreateMapper(roleClaimType: "role");
        var principal = PrincipalWith(new Claim(ClaimTypes.Role, "auditor"));

        var roles = mapper.GetRoles(principal);

        Assert.Equal(["auditor"], roles.ToArray());
    }

    [Fact]
    public void GetRoles_TreatsUriWithSingleDotAsLiteralClaimType()
    {
        // A claim type that is a URI with one dot (e.g., "http://a.com/role") should
        // be treated as a literal claim type, not dot-split into a nested JSON path.
        var mapper = CreateMapper(roleClaimType: "http://a.com/role");
        var principal = PrincipalWith(new Claim("http://a.com/role", "manager"));

        var roles = mapper.GetRoles(principal);

        Assert.Equal(["manager"], roles.ToArray());
    }

    [Fact]
    public void GetRoles_TreatsNamespacedIdentifierAsLiteralClaimType()
    {
        // A claim type with a colon (e.g., "custom:profile.role") is a namespaced identifier
        // (common in AWS Cognito where custom attributes are prefixed "custom:").
        // This should be treated as a literal claim type, not dot-split into outer="custom:profile"
        // and inner="role", which would find nothing.
        var mapper = CreateMapper(roleClaimType: "custom:profile.role");
        var principal = PrincipalWith(new Claim("custom:profile.role", "cognito-admin"));

        var roles = mapper.GetRoles(principal);

        Assert.Equal(["cognito-admin"], roles.ToArray());
    }

    [Fact]
    public void GetRoles_ReturnsEmptyWhenNoRoleClaims()
    {
        var mapper = CreateMapper();
        var principal = PrincipalWith(new Claim("sub", "user-1"));

        Assert.Empty(mapper.GetRoles(principal));
    }

    [Fact]
    public void GetRoles_IgnoresMalformedJsonInsteadOfThrowing()
    {
        var mapper = CreateMapper(roleClaimType: "realm_access.roles");
        var principal = PrincipalWith(new Claim("realm_access", "not-json"));

        Assert.Empty(mapper.GetRoles(principal));
    }

    [Fact]
    public void GetRoles_DeduplicatesCaseInsensitively()
    {
        var mapper = CreateMapper(roleClaimType: "role");
        var principal = PrincipalWith(new Claim("role", "Admin"), new Claim("role", "admin"));

        Assert.Single(mapper.GetRoles(principal));
    }

    [Fact]
    public void GetScopes_SplitsSpaceDelimitedValue()
    {
        var mapper = CreateMapper(scopeClaimType: "scope");
        var principal = PrincipalWith(new Claim("scope", "openid profile qertum-api"));

        var scopes = mapper.GetScopes(principal);

        Assert.Equal(["openid", "profile", "qertum-api"], scopes.OrderBy(s => s).ToArray());
    }

    [Fact]
    public void GetScopes_ReadsRepeatedClaims()
    {
        var mapper = CreateMapper(scopeClaimType: "scp");
        var principal = PrincipalWith(new Claim("scp", "openid"), new Claim("scp", "qertum-api"));

        var scopes = mapper.GetScopes(principal);

        Assert.Equal(["openid", "qertum-api"], scopes.OrderBy(s => s).ToArray());
    }

    [Fact]
    public void IsAdmin_TrueWhenAdminRolePresent()
    {
        var mapper = CreateMapper();
        var principal = PrincipalWith(new Claim("role", AppRoles.Admin));

        Assert.True(mapper.IsAdmin(principal));
    }

    [Fact]
    public void IsAdmin_IsCaseInsensitive()
    {
        var mapper = CreateMapper();
        var principal = PrincipalWith(new Claim("role", "ADMIN"));

        Assert.True(mapper.IsAdmin(principal));
    }

    [Fact]
    public void IsAdmin_FalseWhenOnlyOtherRoles()
    {
        var mapper = CreateMapper();
        var principal = PrincipalWith(new Claim("role", "viewer"));

        Assert.False(mapper.IsAdmin(principal));
    }

    [Fact]
    public void IsAdmin_TrueForKeycloakNestedAdminRole()
    {
        var mapper = CreateMapper(roleClaimType: "realm_access.roles");
        var principal = PrincipalWith(
            new Claim("realm_access", """{"roles":["admin"]}""", "JSON"));

        Assert.True(mapper.IsAdmin(principal));
    }

    [Fact]
    public void GetName_HonoursConfiguredNonDefaultClaimType()
    {
        // Entra v1 tokens have no preferred_username/name; the operator sets
        // Identity:NameClaimType = "upn" to point at the claim that actually carries identity.
        var mapper = CreateMapper(nameClaimType: "upn");
        var principal = PrincipalWith(
            new Claim("upn", "alice@contoso.onmicrosoft.com"),
            new Claim("sub", "00000000-0000-0000-0000-000000000001"));

        Assert.Equal("alice@contoso.onmicrosoft.com", mapper.GetName(principal));
    }

    [Fact]
    public void GetName_FallsBackToStandardChainWhenConfiguredClaimAbsent()
    {
        // The configured claim type is present in config but absent on this particular
        // token (e.g. a provider quirk) — must not report "unknown" while a usable
        // identity claim exists.
        var mapper = CreateMapper(nameClaimType: "upn");
        var principal = PrincipalWith(
            new Claim("preferred_username", "bob"),
            new Claim("sub", "00000000-0000-0000-0000-000000000002"));

        Assert.Equal("bob", mapper.GetName(principal));
    }

    [Fact]
    public void GetName_FallsBackToNameThenSubWhenNothingElseAvailable()
    {
        var mapper = CreateMapper(nameClaimType: "upn");
        var principal = PrincipalWith(new Claim("sub", "00000000-0000-0000-0000-000000000003"));

        Assert.Equal("00000000-0000-0000-0000-000000000003", mapper.GetName(principal));
    }

    [Fact]
    public void GetName_ReturnsUnknownWhenNoIdentityClaimsPresent()
    {
        var mapper = CreateMapper(nameClaimType: "upn");
        var principal = PrincipalWith(new Claim("aud", "qertum-api"));

        Assert.Equal("unknown", mapper.GetName(principal));
    }
}
