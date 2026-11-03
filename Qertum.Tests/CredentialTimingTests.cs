using System.Diagnostics;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Qertum.IdentityService.Stores;
using Qertum.Services;
using Qertum.Services.Est;

namespace Qertum.Tests;

/// <summary>
/// The sign-in page and EST enrollment answer an unknown username and a wrong password identically, but only a known
/// username paid for the password hash, so timing told an attacker which usernames exist. Every refusal now verifies
/// one hash. Measured as a ratio with a wide margin: before, an unknown username took next to no time at all.
/// </summary>
public sealed class CredentialTimingTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("qertum-timing-").FullName;
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { /* best effort */ }
    }

    private static async Task<double> MedianMsAsync(Func<Task> attempt)
    {
        await attempt(); // warm-up
        var samples = new List<double>();
        for (var i = 0; i < 5; i++)
        {
            var watch = Stopwatch.StartNew();
            await attempt();
            samples.Add(watch.Elapsed.TotalMilliseconds);
        }
        samples.Sort();
        return samples[2];
    }

    [Fact]
    public async Task SignIn_AnUnknownUsername_CostsAsMuchAsAWrongPassword()
    {
        var store = new JsonUserStore(NullLogger<JsonUserStore>.Instance, _dir, "Known-Password-1!");

        var wrongPassword = await MedianMsAsync(async () => Assert.Null(await store.ValidateCredentialsAsync("admin", "wrong", Ct)));
        var unknownUser = await MedianMsAsync(async () => Assert.Null(await store.ValidateCredentialsAsync("nobody", "wrong", Ct)));

        Assert.True(unknownUser >= wrongPassword * 0.3, $"unknown {unknownUser:F1} ms vs wrong password {wrongPassword:F1} ms");
    }

    [Fact]
    public async Task EstEnrollment_AnUnknownUsername_CostsAsMuchAsAWrongPassword()
    {
        var options = new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite("DataSource=:memory:").Options;
        await using var db = new CertificateRequestDbContext(options, new EphemeralDataProtectionProvider());
        await db.Database.OpenConnectionAsync(Ct);
        await db.Database.EnsureCreatedAsync(Ct);
        var service = new EstEnrollmentCredentialService(db, new NullAuditLogService());
        await service.CreateAsync("device-1", "Known-Password-1!", "admin", cancellationToken: Ct);

        var wrongPassword = await MedianMsAsync(async () => await service.CheckAsync("device-1", "wrong", Ct));
        var unknownUser = await MedianMsAsync(async () => await service.CheckAsync("nobody", "wrong", Ct));

        Assert.True(unknownUser >= wrongPassword * 0.3, $"unknown {unknownUser:F1} ms vs wrong password {wrongPassword:F1} ms");
    }
}

file sealed class NullAuditLogService : IAuditLogService
{
    public Task LogAsync(string action, string performedBy, Guid? resourceId = null,
        string? resourceName = null, string? detail = null, CancellationToken cancellationToken = default)
        => Task.CompletedTask;

    public Task<IReadOnlyList<AuditLogEntry>> GetAllAsync(int page = 1, int pageSize = 100,
        CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlyList<AuditLogEntry>>([]);
}
