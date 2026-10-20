using Qertum.AcmeService;
using Qertum.Services;
using Qertum.Services.Acme;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

var connectionString = builder.Configuration.GetConnectionString("CertificateRequests");
builder.Services.AddCustomCaServices(connectionString, builder.Environment.EnvironmentName);
// Registered before AddAcmeServices so Redis and its connection multiplexer are available for atomic nonce consumption.
builder.AddQertumDistributedCache();
builder.Services.AddAcmeServices();
builder.Services.AddHostedService<AcmeChallengeVerificationService>();
builder.Services.AddAcmeRateLimiting();
builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics => metrics.AddMeter(ProtocolMetrics.MeterName));

var app = builder.Build();

app.UseRouting();
app.UseRateLimiter();

// Resolve the base URL for directory and resource links.
// In Aspire, Acme__BaseUrl is injected from the service's own endpoint.
var baseUrl = (app.Configuration["Acme:BaseUrl"] ?? "").TrimEnd('/');

app.MapAcmeEndpoints(baseUrl);
app.MapDefaultEndpoints();

app.Run();

public class AcmeServiceProgram { }
