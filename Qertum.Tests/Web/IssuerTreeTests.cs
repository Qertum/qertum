using Qertum.Services;
using Qertum.Web.Components.Issuers;

namespace Qertum.Tests.Web;

public sealed class IssuerTreeTests
{
    private static IssuerResponse Issuer(string name, IssuerKind kind, IssuerId? parent = null, int minute = 0) =>
        new(new IssuerId(Guid.NewGuid()), name, kind, parent, IssuerKeyCustody.Online, IssuerStatus.Active, false,
            null, null, null, null, null, null, [], [], [], [], null, null,
            new DateTime(2026, 9, 27, 0, minute, 0, DateTimeKind.Utc), null, null, null, null);

    [Fact]
    public void RootsComeFirst_EachFollowedByItsDescendants()
    {
        var rootA = Issuer("A", IssuerKind.Root, minute: 0);
        var rootB = Issuer("B", IssuerKind.Root, minute: 1);
        var childB = Issuer("B1", IssuerKind.Intermediate, rootB.Id, minute: 2);
        var childA = Issuer("A1", IssuerKind.Intermediate, rootA.Id, minute: 3);
        var grandchildA = Issuer("A1x", IssuerKind.Intermediate, childA.Id, minute: 4);

        var lines = IssuerTree.Build([grandchildA, childB, rootB, childA, rootA]);

        Assert.Equal(["A", "A1", "A1x", "B", "B1"], lines.Select(l => l.Issuer.Name));
        Assert.Equal([0, 1, 2, 0, 1], lines.Select(l => l.Depth));
    }

    [Fact]
    public void Orphans_AreListedAtTheEnd()
    {
        var orphan = Issuer("Lost", IssuerKind.Intermediate, new IssuerId(Guid.NewGuid()));
        var root = Issuer("Root", IssuerKind.Root);

        Assert.Equal(["Root", "Lost"], IssuerTree.Build([orphan, root]).Select(l => l.Issuer.Name));
    }

    [Fact]
    public void AParentCycle_StillListsEveryIssuerOnce()
    {
        var a = Issuer("A", IssuerKind.Intermediate);
        var b = Issuer("B", IssuerKind.Intermediate, a.Id, minute: 1);
        a = a with { ParentIssuerId = b.Id };

        Assert.Equal(2, IssuerTree.Build([a, b]).Count);
    }
}
