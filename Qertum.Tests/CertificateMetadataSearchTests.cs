using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests;

public sealed class CertificateMetadataSearchTests
{
    private static async Task<MetadataTestHost> SeedAsync()
    {
        var host = await MetadataTestHost.CreateAsync();
        host.Db.CertificateRequests.AddRange(
            Row("a.contoso.local", new CertificateMetadata { OwnerTeam = "Payments Platform" }),
            Row("b.contoso.local", new CertificateMetadata { TargetSystem = "billing-gw" }),
            Row("c.contoso.local", new CertificateMetadata { TicketReference = "OPS-4711" }),
            Row("d.contoso.local", new CertificateMetadata { ContactEmail = "secret.contact@contoso.local" }));
        await host.Db.SaveChangesAsync(TestContext.Current.CancellationToken);
        return host;
    }

    private static CertificateRequest Row(string commonName, CertificateMetadata metadata) => new()
    {
        CommonName = commonName, RequestedBy = "alice", Status = CertificateRequestStatus.Pending, Metadata = metadata
    };

    private static async Task<string[]> SearchAsync(MetadataTestHost host, string term) =>
        [.. (await host.Service.GetAllAsync(search: term, cancellationToken: TestContext.Current.CancellationToken))
            .Items.Select(r => r.CommonName).Order(StringComparer.Ordinal)];

    [Fact]
    public async Task Search_MatchesOwnerTeam_RegardlessOfCase()
    {
        await using var host = await SeedAsync();
        Assert.Equal(["a.contoso.local"], await SearchAsync(host, "payments"));
    }

    [Fact]
    public async Task Search_MatchesTargetSystem()
    {
        await using var host = await SeedAsync();
        Assert.Equal(["b.contoso.local"], await SearchAsync(host, "billing"));
    }

    [Fact]
    public async Task Search_MatchesTheTicketReference()
    {
        await using var host = await SeedAsync();
        Assert.Equal(["c.contoso.local"], await SearchAsync(host, "OPS-4711"));
    }

    [Fact]
    public async Task Search_DoesNotMatchTheContactEmail()
    {
        await using var host = await SeedAsync();
        Assert.Empty(await SearchAsync(host, "secret.contact"));
    }

    [Fact]
    public async Task Search_TreatsLikeWildcardsInMetadataLiterally()
    {
        await using var host = await SeedAsync();
        // "_" would match any character if it were not escaped: OPS_4711 must not find OPS-4711.
        Assert.Empty(await SearchAsync(host, "OPS_4711"));
    }
}
