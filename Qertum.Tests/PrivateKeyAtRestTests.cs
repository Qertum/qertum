using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests;

/// <summary>
/// Both private keys of a request are encrypted at rest. The second key of a paired or hybrid
/// pair (<see cref="CertificateRequest.PqcPrivateKeyPem"/>) was written as plain PEM until 1.0.0,
/// so the API also re-encrypts plain rows once at start.
/// </summary>
public sealed class PrivateKeyAtRestTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private const string KeyPem = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----";
    private const string PqcKeyPem = "-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----";

    private static async Task<(string? Key, string? PqcKey)> RawColumnsAsync(CertificateRequestDbContext db)
    {
        var connection = db.Database.GetDbConnection();
        if (connection.State != System.Data.ConnectionState.Open) await connection.OpenAsync(Ct);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT PrivateKeyPem, PqcPrivateKeyPem FROM CertificateRequests";
        await using var reader = await command.ExecuteReaderAsync(Ct);
        Assert.True(await reader.ReadAsync(Ct), "row not found by raw query");
        return (reader.IsDBNull(0) ? null : reader.GetString(0), reader.IsDBNull(1) ? null : reader.GetString(1));
    }

    private static async Task<CertificateRequest> AddRequestAsync(CertificateRequestDbContext db)
    {
        var request = new CertificateRequest
        {
            CommonName = "pair.example.test",
            Type = "WebServer",
            PrivateKeyPem = KeyPem,
            PqcPrivateKeyPem = PqcKeyPem
        };
        db.CertificateRequests.Add(request);
        await db.SaveChangesAsync(Ct);
        db.ChangeTracker.Clear();
        return request;
    }

    [Fact]
    public async Task BothKeysAreEncryptedInTheDatabaseAndReadBackAsPem()
    {
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();
        var request = await AddRequestAsync(db);

        var (key, pqcKey) = await RawColumnsAsync(db);
        Assert.False(key!.StartsWith("-----BEGIN", StringComparison.Ordinal), "PrivateKeyPem is stored in plain text");
        Assert.False(pqcKey!.StartsWith("-----BEGIN", StringComparison.Ordinal), "PqcPrivateKeyPem is stored in plain text");

        var read = await db.CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == request.Id, Ct);
        Assert.Equal(KeyPem, read.PrivateKeyPem);
        Assert.Equal(PqcKeyPem, read.PqcPrivateKeyPem);
    }

    [Fact]
    public async Task PlainKeysWrittenByAnOlderVersionAreEncryptedOnce()
    {
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();
        var request = await AddRequestAsync(db);
        await db.Database.ExecuteSqlRawAsync(
            "UPDATE CertificateRequests SET PrivateKeyPem = {0}, PqcPrivateKeyPem = {1}", [KeyPem, PqcKeyPem], Ct);

        var first = await PrivateKeyAtRest.EncryptPlainKeysAsync(db, Ct);
        var second = await PrivateKeyAtRest.EncryptPlainKeysAsync(db, Ct);

        Assert.Equal(1, first);
        Assert.Equal(0, second);
        var (key, pqcKey) = await RawColumnsAsync(db);
        Assert.False(key!.StartsWith("-----BEGIN", StringComparison.Ordinal));
        Assert.False(pqcKey!.StartsWith("-----BEGIN", StringComparison.Ordinal));
        db.ChangeTracker.Clear();
        var read = await db.CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == request.Id, Ct);
        Assert.Equal((KeyPem, PqcKeyPem), (read.PrivateKeyPem, read.PqcPrivateKeyPem));
    }
}
