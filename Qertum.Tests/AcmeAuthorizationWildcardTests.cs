using Qertum.Services;
using Qertum.Services.Acme;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Qertum.Tests;

public sealed class AcmeAuthorizationWildcardTests
{
    [Fact]
    public async Task WildcardFlag_RoundTripsThroughTheDatabase()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);

        var options = new DbContextOptionsBuilder<CertificateRequestDbContext>()
            .UseSqlite(connection).Options;

        await using (var db = new CertificateRequestDbContext(options, new EphemeralDataProtectionProvider()))
        {
            await db.Database.EnsureCreatedAsync(ct);
            var account = new AcmeAccount { JwkThumbprint = "t", PublicKeyJwk = "{}" };
            var order = new AcmeOrder
            {
                Account = account,
                IdentifiersJson = "[{\"type\":\"dns\",\"value\":\"*.example.com\"}]",
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            };
            db.AcmeAuthorizations.Add(new AcmeAuthorization
            {
                Order = order,
                IdentifierValue = "example.com",
                Wildcard = true,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            });
            await db.SaveChangesAsync(ct);
        }

        await using (var verify = new CertificateRequestDbContext(options, new EphemeralDataProtectionProvider()))
        {
            var auth = await verify.AcmeAuthorizations.AsNoTracking().SingleAsync(ct);
            Assert.True(auth.Wildcard);
            Assert.Equal("example.com", auth.IdentifierValue);
        }
    }
}
