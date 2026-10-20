using Bunit;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Web.Components.Layout;

namespace Qertum.Tests.Web;

/// <summary>
/// "All Requests" and "Pending" share a path and differ only by query, so a plain NavLink would
/// highlight both at once.
/// </summary>
public sealed class QueryNavLinkTests : IDisposable
{
    private readonly BunitContext context = new();

    public void Dispose() => context.Dispose();

    // What NavMenu passes to "All Requests": the statuses another sidebar item already names.
    private static readonly string[] LinkedElsewhere = ["Pending"];

    private IRenderedComponent<QueryNavLink> RenderLink(string href, string[]? linkedElsewhere) =>
        context.Render<QueryNavLink>(p =>
        {
            p.AddUnmatched("href", href).AddChildContent("link");
            if (linkedElsewhere is not null)
                p.Add(l => l.StatusesLinkedElsewhere, linkedElsewhere);
        });

    private bool IsActive(string href, string currentUri, string[]? linkedElsewhere = null)
    {
        context.Services.GetRequiredService<NavigationManager>().NavigateTo(currentUri);
        return RenderLink(href, linkedElsewhere).Find("a").ClassList.Contains("active");
    }

    [Theory]
    [InlineData("certificate-requests", "certificate-requests", true)]
    [InlineData("certificate-requests", "certificate-requests?status=Pending", false)]
    [InlineData("certificate-requests?status=Pending", "certificate-requests?status=Pending", true)]
    [InlineData("certificate-requests?status=Pending", "certificate-requests?status=pending", true)]
    [InlineData("certificate-requests?status=Pending", "certificate-requests", false)]
    [InlineData("certificate-requests?status=Pending", "certificate-requests?status=Approved", false)]
    [InlineData("certificate-requests", "certificate-requests/5f7b1a52-3b1f-4c4e-9d25-0d1f6f6a8c11", true)]
    [InlineData("certificate-requests", "certificate-requests-archive", false)]
    [InlineData("certificate-requests", "certificates", false)]
    public void ActiveOnlyWhenPathAndQueryMatch(string href, string currentUri, bool expected) =>
        Assert.Equal(expected, IsActive(href, currentUri, LinkedElsewhere));

    // Paging and any other query key are views of the same menu item, not a different one.
    [Theory]
    [InlineData("certificate-requests?status=Pending", "certificate-requests?status=Pending&page=2", true)]
    [InlineData("certificate-requests?status=Pending", "certificate-requests?page=2&status=Pending", true)]
    [InlineData("certificate-requests", "certificate-requests?page=3", true)]
    public void IgnoresQueryKeysOtherThanStatus(string href, string currentUri, bool expected) =>
        Assert.Equal(expected, IsActive(href, currentUri, LinkedElsewhere));

    // A chip with no sidebar item of its own (Approved, Issued, Denied, Revoked) is still the
    // request list, so "All Requests" stays highlighted rather than nothing at all.
    [Theory]
    [InlineData("certificate-requests?status=Approved", true)]
    [InlineData("certificate-requests?status=Issued", true)]
    [InlineData("certificate-requests?status=Denied", true)]
    [InlineData("certificate-requests?status=Revoked&page=2", true)]
    [InlineData("certificate-requests?status=Pending", false)]
    [InlineData("certificate-requests?status=pending", false)]
    public void UnfilteredLinkClaimsStatusesNoOtherItemNames(string currentUri, bool expected) =>
        Assert.Equal(expected, IsActive("certificate-requests", currentUri, LinkedElsewhere));

    [Fact]
    public void ExactlyOneRequestsItemIsActiveForEveryChip()
    {
        foreach (var status in new[] { "", "Pending", "Approved", "Issued", "Denied", "Revoked" })
        {
            var uri = status.Length == 0 ? "certificate-requests" : $"certificate-requests?status={status}";
            var active = new[]
            {
                IsActive("certificate-requests", uri, LinkedElsewhere),
                IsActive("certificate-requests?status=Pending", uri),
            }.Count(a => a);
            Assert.True(active == 1, $"{active} request menu items active for '{uri}'");
        }
    }
}
