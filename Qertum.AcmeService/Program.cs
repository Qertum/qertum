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
// The isolated E2E fixture can exercise HTTP-01 without occupying the host's port 80.
if (builder.Environment.IsDevelopment() && builder.Configuration["Acme:E2eHttp01Port"] is { } portValue)
{
    if (!int.TryParse(portValue, out var port) || port is < 1024 or > 65535)
        throw new InvalidOperationException("Acme:E2eHttp01Port must be between 1024 and 65535.");
    builder.Services.AddHttpClient("acme-challenge")
        .AddHttpMessageHandler(() => new E2eHttp01PortHandler(port));
}
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

internal sealed class E2eHttp01PortHandler(int port) : DelegatingHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var uri = request.RequestUri!;
        if (uri.Scheme == Uri.UriSchemeHttp && uri.Port == 80 &&
            (uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
             uri.Host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase)))
            request.RequestUri = new UriBuilder(uri) { Port = port }.Uri;
        return base.SendAsync(request, cancellationToken);
    }
}
