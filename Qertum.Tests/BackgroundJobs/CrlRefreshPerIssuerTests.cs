using Microsoft.Extensions.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Qertum.QueueConsumer;
using Qertum.Services;
using Qertum.Services.BackgroundJobs;
using Qertum.Services.Issuers;

namespace Qertum.Tests.BackgroundJobs;

public sealed class CrlRefreshPerIssuerTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static CrlRefreshScheduler Scheduler(BackgroundJobTestHost host) =>
        new(host.Services.GetRequiredService<IServiceScopeFactory>(), host.Services.GetRequiredService<IBackgroundJobSignal>(),
            Options.Create(new CrlRefreshOptions()), NullLogger<CrlRefreshScheduler>.Instance, host.Clock,
            new DistributedCacheMode(IsShared: true));

    /// <summary>A root in its own issuer directory, generated with the host's key ring.</summary>
    private static async Task<Issuer> AddRootAsync(BackgroundJobTestHost host, string name, IssuerStatus status,
        IssuerKeyCustody custody = IssuerKeyCustody.Online)
    {
        var issuer = new Issuer { Name = name, Kind = IssuerKind.Root, KeyCustody = custody, Status = status, CreatedAtUtc = host.Clock.GetUtcNow().UtcDateTime };
        var storage = host.Services.GetRequiredService<IssuerStorage>();
        var generator = new CertificateGenerator(host.DataProtection, storage.OptionsFor(issuer),
            NullLogger<CertificateGenerator>.Instance, timeProvider: host.Clock);
        generator.GenerateCa(new GenerateCaRequest { CommonName = name, ValidityDays = 365 });
        issuer.CertificatePem = generator.GetCaCertificatePem();
        IssuerCertificateFacts.Read(issuer.CertificatePem).ApplyTo(issuer);
        if (custody == IssuerKeyCustody.Offline) storage.DeleteFiles(issuer);
        await using var db = host.Database.CreateContext();
        db.Issuers.Add(issuer);
        await db.SaveChangesAsync(Ct);
        await host.Services.GetRequiredService<IIssuerRegistry>().InvalidateAsync(Ct);
        return issuer;
    }

    [Fact]
    public async Task CheckAll_QueuesOneJobPerOnlineIssuerThatCanSignRevocation()
    {
        await using var host = BackgroundJobTestHost.Create();
        var registry = host.Services.GetRequiredService<IIssuerRegistry>();
        await registry.GetDefaultAsync(Ct); // bootstraps the legacy issuer
        var retired = await AddRootAsync(host, "Retired Root", IssuerStatus.Retired);
        await AddRootAsync(host, "Offline Root", IssuerStatus.Active, IssuerKeyCustody.Offline);
        await AddRootAsync(host, "Archived Root", IssuerStatus.Archived);

        var jobs = await Scheduler(host).CheckAllAsync(Ct);

        Assert.Equal(
            new[] { CrlRefreshJobHandler.ConcurrencyKey, $"{CrlRefreshJobHandler.ConcurrencyKey}:{retired.Id}" }.Order(),
            jobs.Select(j => j.ConcurrencyKey!).Order());
        Assert.Null(jobs.Single(j => j.ConcurrencyKey == CrlRefreshJobHandler.ConcurrencyKey).PayloadJson);
        Assert.Contains(retired.Id.ToString(), jobs.Single(j => j.ConcurrencyKey != CrlRefreshJobHandler.ConcurrencyKey).PayloadJson);
    }

    [Fact]
    public async Task Handler_WithAnIssuerPayload_PublishesThatIssuersCrlAndBase()
    {
        await using var host = BackgroundJobTestHost.Create();
        var second = await AddRootAsync(host, "Second Root", IssuerStatus.Active);
        await using var scope = host.Services.CreateAsyncScope();
        var handler = new CrlRefreshJobHandler(host.Services.GetRequiredService<IIssuerRegistry>(),
            scope.ServiceProvider.GetRequiredService<CrlPublisher>());

        var result = await handler.HandleAsync(new BackgroundJob
        {
            JobType = WellKnownJobTypes.CrlRefresh,
            PayloadJson = $"{{\"issuerId\":\"{second.Id}\"}}"
        }, Ct);

        Assert.StartsWith("crlNumber=", result);
        Assert.NotNull(await host.Services.GetRequiredService<IDistributedCache>().GetAsync(CrlCache.KeyFor(second), Ct));
        await using var db = host.Database.CreateContext();
        Assert.NotNull((await db.Issuers.SingleAsync(i => i.Id == second.Id, Ct)).BaseCrlNumber);
    }

    [Fact]
    public async Task Handler_WithoutPayload_PublishesTheLegacyCrl_EvenWhenAnotherIssuerIsDefault()
    {
        await using var host = BackgroundJobTestHost.Create();
        var registry = host.Services.GetRequiredService<IIssuerRegistry>();
        var legacy = (await registry.GetDefaultAsync(Ct))!.Issuer;
        var second = await AddRootAsync(host, "New Default", IssuerStatus.Active);
        await using (var db = host.Database.CreateContext())
        {
            await db.Issuers.Where(i => i.Id == legacy.Id).ExecuteUpdateAsync(x => x.SetProperty(i => i.IsDefault, false), Ct);
            await db.Issuers.Where(i => i.Id == second.Id).ExecuteUpdateAsync(x => x.SetProperty(i => i.IsDefault, true), Ct);
        }
        await registry.InvalidateAsync(Ct);
        await using var scope = host.Services.CreateAsyncScope();
        var handler = new CrlRefreshJobHandler(registry, scope.ServiceProvider.GetRequiredService<CrlPublisher>());

        await handler.HandleAsync(new BackgroundJob { JobType = WellKnownJobTypes.CrlRefresh }, Ct);

        Assert.NotNull(await host.Services.GetRequiredService<IDistributedCache>().GetAsync(CrlCache.Key, Ct));
        Assert.Null(await host.Services.GetRequiredService<IDistributedCache>().GetAsync(CrlCache.KeyFor(second), Ct));
    }

    [Fact]
    public async Task Handler_ForAnArchivedIssuer_CompletesSkipped()
    {
        await using var host = BackgroundJobTestHost.Create();
        var archived = await AddRootAsync(host, "Archived", IssuerStatus.Archived);
        await using var scope = host.Services.CreateAsyncScope();
        var handler = new CrlRefreshJobHandler(host.Services.GetRequiredService<IIssuerRegistry>(),
            scope.ServiceProvider.GetRequiredService<CrlPublisher>());

        var result = await handler.HandleAsync(new BackgroundJob
        {
            JobType = WellKnownJobTypes.CrlRefresh,
            PayloadJson = $"{{\"issuerId\":\"{archived.Id}\"}}"
        }, Ct);

        Assert.StartsWith("skipped", result);
    }
}
