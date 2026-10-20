using Qertum.Services;

namespace Qertum.Tests.Roles;

public sealed class PermissionDescriptionsTests
{
    [Fact]
    public void EveryPermissionHasExactlyOneDescription()
    {
        Assert.Equal(
            AppPermissions.All.OrderBy(p => p, StringComparer.Ordinal),
            AppPermissions.Descriptions.Keys.OrderBy(p => p, StringComparer.Ordinal));
        Assert.All(AppPermissions.Descriptions.Values, d => Assert.False(string.IsNullOrWhiteSpace(d)));
    }
}
