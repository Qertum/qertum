using Microsoft.Extensions.DependencyInjection.Extensions;
using Qertum.Services;
using Qertum.Services.Est;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

var connectionString = builder.Configuration.GetConnectionString("CertificateRequests");
builder.Services.AddCustomCaServices(connectionString, builder.Environment.EnvironmentName);
builder.AddQertumDistributedCache();
builder.Services.AddEstRateLimiting();
builder.Services.TryAddSingleton<ProtocolMetrics>();
builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics => metrics.AddMeter(ProtocolMetrics.MeterName));

builder.Services.AddHealthChecks()
    .AddCustomCaHealthChecks();

// mTLS for /simplereenroll: the client's EST-issued certificate arrives as the TLS client
// certificate, so Kestrel must request (not require — /simpleenroll and the no-auth routes
// don't present one) a client certificate on this binding, and take it without platform chain validation
// (the endpoint validates it; see EstClientCertificateTls). A reverse proxy terminating TLS in
// front of this service must forward the client cert or use TCP passthrough.
builder.Services.Configure<Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions>(options =>
{
    options.ConfigureHttpsDefaults(EstClientCertificateTls.Configure);
});

var app = builder.Build();

app.UseRouting();
app.UseRateLimiter();

app.MapEstEndpoints();
app.MapDefaultEndpoints();

app.Run();

public class EstServiceProgram { }
