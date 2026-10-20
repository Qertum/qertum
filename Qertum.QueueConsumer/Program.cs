using Qertum.Services.Approvals;
using Qertum.Services.BulkOperations;
using Microsoft.EntityFrameworkCore;
using Qertum.QueueConsumer;
using Qertum.Services;

var builder = Host.CreateApplicationBuilder(args);

builder.AddServiceDefaults();
// Shared with the API so finalising a revocation can evict the published CRL.
builder.AddQertumDistributedCache();
builder.Services.AddCustomCaServices(builder.Configuration.GetConnectionString("CertificateRequests"), builder.Environment.EnvironmentName);
builder.Services.AddBulkOperations();
builder.Services.AddApprovals();

builder.Services.AddQueueConsumerOptions();

builder.Services.AddHealthChecks()
    .AddCustomCaHealthChecks();

// Register queue metrics and add the meter to the OpenTelemetry pipeline.
builder.Services.AddQueueConsumerMetrics();
builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics => metrics
        .AddMeter(CertificateQueueMetrics.MeterName)
        .AddMeter(OperationsMetrics.MeterName));

builder.Services.AddHostedService<CertificateRequestQueueConsumer>();
builder.Services.AddWebhookDeliveryService();
builder.Services.AddBackgroundJobs();

var host = builder.Build();

// Ensure the singleton is created (and the gauge registered) before the host starts.
_ = host.Services.GetRequiredService<CertificateQueueMetrics>();

// Wait for the schema rather than creating it. ApiService is the only writer of persistence
// shape and applies it with Database.Migrate(); EnsureCreated here would race that on a fresh
// deployment and could win, producing a schema with no __EFMigrationsHistory that Migrate()
// then refuses, taking ApiService down on first boot. Waiting is also required: the consumer's
// dequeue loop does not catch a missing-table exception, and BackgroundServiceExceptionBehavior
// defaults to StopHost, so starting before the schema exists would kill this host anyway.
{
    var startupLogger = host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("QueueConsumer.Startup");
    var clock = host.Services.GetRequiredService<TimeProvider>();
    var deadline = clock.GetUtcNow() + TimeSpan.FromMinutes(5);
    var reported = false;

    while (true)
    {
        await using var scope = host.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        try
        {
            // Touches the table the dequeue loop reads first, so a database that exists but has
            // not been migrated yet does not count as ready.
            await db.CertificateRequests.AnyAsync();
            // The background job processor reads this table first; an ApiService that has not
            // applied the BackgroundJobs migration yet does not count as ready either.
            await db.BackgroundJobs.AnyAsync();
            // The registry reads Issuers on the first claim.
            await db.Issuers.AnyAsync();
            break;
        }
        catch (Exception ex)
        {
            if (clock.GetUtcNow() >= deadline)
            {
                startupLogger.LogCritical(ex,
                    "Certificate request schema was not available within 5 minutes. ApiService applies it on its own startup; verify it is running and that the connection string points at the same database. Path: {DbPath}",
                    db.Database.GetConnectionString());
                Environment.Exit(1);
            }

            if (!reported)
            {
                startupLogger.LogInformation(
                    "Waiting for ApiService to apply the certificate request schema before starting the queue consumer.");
                reported = true;
            }

            await Task.Delay(TimeSpan.FromSeconds(2));
        }
    }
}

await host.RunAsync();
