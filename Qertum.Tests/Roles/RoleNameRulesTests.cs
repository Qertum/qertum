using Qertum.Services;

namespace Qertum.Tests.Roles;

public sealed class RoleNameRulesTests
{
    [Theory]
    [InlineData("operators")]
    [InlineData("Ops.Team_1-a")]
    [InlineData("realm role with spaces")]
    [InlineData("urn:example:role")]
    public void Accepts(string role) => Assert.True(RoleNameRules.IsValid(role));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ops")]
    [InlineData("ops ")]
    [InlineData("a/b")]
    [InlineData("ops")]
    public void Rejects(string? role)
    {
        Assert.False(RoleNameRules.TryValidate(role, out var error));
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Fact]
    public void LengthBoundary()
    {
        Assert.True(RoleNameRules.IsValid(new string('a', 128)));
        Assert.False(RoleNameRules.IsValid(new string('a', 129)));
    }
}
