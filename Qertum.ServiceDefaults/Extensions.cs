using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using OpenTelemetry;
using Serilog;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

namespace Microsoft.Extensions.Hosting;

// Adds common Aspire services: service discovery, resilience, health checks, and OpenTelemetry.
// This project should be referenced by each service project in your solution.
// To learn more about using this project, see https://aka.ms/dotnet/aspire/service-defaults
public static class Extensions
{
    /// <summary>
    /// Registers the distributed cache every service shares. When a <c>cache</c> connection string is
    /// present the cache is Redis, so entries written by one instance are seen by all of them; without
    /// one it falls back to an in-memory cache, which is correct only for a single-instance run.
    /// </summary>
    /// <remarks>
    /// What the cache holds is state that must not differ between instances: the CRL, whose per-process
    /// copies let one node call a certificate revoked while another still calls it valid, and ACME
    /// nonces, which a second instance would otherwise reject as unknown.
    /// </remarks>
    public static TBuilder AddQertumDistributedCache<TBuilder>(this TBuilder builder, string connectionName = "cache")
        where TBuilder : IHostApplicationBuilder
    {
        var shared = !string.IsNullOrWhiteSpace(builder.Configuration.GetConnectionString(connectionName));
        if (shared)
            builder.AddRedisDistributedCache(connectionName, configureOptions: Qertum.ServiceDefaults.QertumRedis.ApplyResilience);
        else
            builder.Services.AddDistributedMemoryCache();
        builder.Services.AddSingleton(new DistributedCacheMode(shared));

        return builder;
    }

    private const string HealthEndpointPath = "/health";
    private const string AlivenessEndpointPath = "/alive";

    public static TBuilder AddServiceDefaults<TBuilder>(this TBuilder builder) where TBuilder : IHostApplicationBuilder
    {
        builder.ConfigureOpenTelemetry();

        builder.AddDefaultHealthChecks();

        builder.Services.AddServiceDiscovery();

        builder.Services.ConfigureHttpClientDefaults(http =>
        {
            // Turn on resilience by default; requests marked with HttpRetryOptOut are sent once.
            http.AddStandardResilienceHandler(HttpRetryOptOut.Apply);

            // Turn on service discovery by default
            http.AddServiceDiscovery();
        });

        // Uncomment the following to restrict the allowed schemes for service discovery.
        // builder.Services.Configure<ServiceDiscoveryOptions>(options =>
        // {
        //     options.AllowedSchemes = ["https"];
        // });

        return builder;
    }

    public static TBuilder ConfigureOpenTelemetry<TBuilder>(this TBuilder builder) where TBuilder : IHostApplicationBuilder
    {
        // Serilog is the logging implementation in every host; code keeps logging through ILogger<T>.
        // It reads its levels from the "Serilog" section and writes the console itself, so the default
        // providers are cleared to avoid printing every line twice. writeToProviders forwards each
        // event, synchronously and inside the caller's Activity, to the providers still registered:
        // the OpenTelemetry one below (the Aspire dashboard, with trace context) and any a test adds.
        builder.Logging.ClearProviders();
        builder.Logging.AddOpenTelemetry(logging =>
        {
            logging.IncludeFormattedMessage = true;
            logging.IncludeScopes = true;
        });
        builder.Services.AddSerilog(
            (_, logger) => logger
                .ReadFrom.Configuration(builder.Configuration)
                .Enrich.FromLogContext()
                .Enrich.With<Qertum.ServiceDefaults.Logging.TraceIdEnricher>()
                .WriteTo.Console(
                    outputTemplate: Qertum.ServiceDefaults.Logging.ConsoleLog.OutputTemplate,
                    formatProvider: System.Globalization.CultureInfo.InvariantCulture),
            // Each host keeps its own logger. Without this Serilog replaces the static Log.Logger and
            // routes every host's ILoggerFactory through it, so hosts side by side (tests) lose events.
            preserveStaticLogger: true,
            writeToProviders: true);

        builder.Services.AddOpenTelemetry()
            .WithMetrics(metrics =>
            {
                metrics.AddAspNetCoreInstrumentation()
                    .AddHttpClientInstrumentation()
                    .AddRuntimeInstrumentation();
            })
            .WithTracing(tracing =>
            {
                tracing.AddSource(builder.Environment.ApplicationName)
                    .AddAspNetCoreInstrumentation(aspnet =>
                        // Exclude health check requests from tracing
                        aspnet.Filter = context =>
                            !context.Request.Path.StartsWithSegments(HealthEndpointPath)
                            && !context.Request.Path.StartsWithSegments(AlivenessEndpointPath)
                    )
                    // Uncomment the following line to enable gRPC instrumentation (requires the OpenTelemetry.Instrumentation.GrpcNetClient package)
                    //.AddGrpcClientInstrumentation()
                    .AddHttpClientInstrumentation();
            });

        builder.AddOpenTelemetryExporters();

        return builder;
    }

    private static void AddOpenTelemetryExporters<TBuilder>(this TBuilder builder) where TBuilder : IHostApplicationBuilder
    {
        var useOtlpExporter = !string.IsNullOrWhiteSpace(builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"]);

        if (useOtlpExporter)
        {
            builder.Services.AddOpenTelemetry().UseOtlpExporter();
        }
    }

    public static TBuilder AddDefaultHealthChecks<TBuilder>(this TBuilder builder) where TBuilder : IHostApplicationBuilder
    {
        builder.Services.AddHealthChecks()
            // Add a default liveness check to ensure app is responsive
            .AddCheck("self", () => HealthCheckResult.Healthy(), ["live"]);

        return builder;
    }

    /// <summary>
    /// Resolves the IdentityService authority URL with fallback chain:
    /// Aspire service-discovery → explicit config → localhost default.
    /// </summary>
    public static string ResolveIdentityServiceAuthority(this IConfiguration configuration, string defaultUrl = "https://localhost:7099")
    {
        return configuration["Services:identityservice:https:0"]
               ?? configuration["Services:identityservice:http:0"]
               ?? configuration["IdentityService:Authority"]
               ?? defaultUrl;
    }

    public static WebApplication MapDefaultEndpoints(this WebApplication app)
    {
        // Adding health checks endpoints to applications in non-development environments has security implications.
        // See https://aka.ms/dotnet/aspire/healthchecks for details before enabling these endpoints in non-development environments.
        if (app.Environment.IsDevelopment())
        {
            // All health checks must pass for app to be considered ready to accept traffic after starting
            app.MapHealthChecks(HealthEndpointPath).AllowAnonymous();

            // Only health checks tagged with the "live" tag must pass for app to be considered alive
            app.MapHealthChecks(AlivenessEndpointPath, new HealthCheckOptions
            {
                Predicate = r => r.Tags.Contains("live")
            }).AllowAnonymous();
        }

        return app;
    }
}

/// <summary>
/// Whether <see cref="Extensions.AddQertumDistributedCache{TBuilder}"/> registered a cache shared by
/// every process (Redis) or one private to this process (memory).
/// </summary>
public sealed record DistributedCacheMode(bool IsShared);
