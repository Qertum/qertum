using Qertum.Services.Approvals;
using Qertum.Services.BulkOperations;
using Qertum.Services.Issuers;
using System.Threading.RateLimiting;
using Qertum.Services;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Qertum.Services.Auth;
using Qertum.Services.Policies;
using Qertum.ApiService;
using Qertum.Services.Webhooks;
using Microsoft.Extensions.Options;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Add service defaults & Aspire client integrations.
builder.AddServiceDefaults();

// Add services to the container.
// Framework-built problems (status-code pages, Results.Problem) get the same bare trace id the header and
// the console log use, instead of the long traceparent form.
builder.Services.AddProblemDetails(options => options.CustomizeProblemDetails = context =>
    context.ProblemDetails.Extensions["traceId"] = Qertum.Services.CorrelationIds.For(context.HttpContext));
builder.Services.AddCustomCaServices(builder.Configuration.GetConnectionString("CertificateRequests"), builder.Environment.EnvironmentName);
builder.Services.AddBulkOperations();
builder.Services.AddApprovals();
builder.Services.AddWebhookDestinationPolicyOptions();

// Named HTTP client for the Identity Service health check — no resilience handler so the
// check fails fast instead of retrying. Timeout is set at the handler level.
builder.Services.AddHttpClient(IdentityServiceHealthCheck.ClientName)
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler())
    .ConfigureHttpClient(c => c.Timeout = TimeSpan.FromSeconds(5));

builder.Services.AddHealthChecks()
    .AddCustomCaHealthChecks()
    .AddCheck<IdentityServiceHealthCheck>("identity-service", tags: ["ready"]);

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Standard OIDC bearer-token validation. Tokens are validated locally against the issuer's
// JWKS, so any OpenID Connect provider works without provider-specific packages or a
// shared introspection secret. Trade-off: a revoked token is accepted until it expires,
// which matches the previous behavior since introspection results were cached for the
// token lifetime. Keep access-token lifetimes short at the issuer.
var identityOptions = builder.Services.AddQertumJwtAuthentication(
    builder.Configuration,
    builder.Environment.IsDevelopment());

// The /crl endpoint (ApiEndpointMappings.MapCrlEndpoint) caches the generated CRL here. Shared
// rather than per-process: two instances each caching their own CRL can disagree about whether a
// certificate is revoked for as long as the entries live.
builder.AddQertumDistributedCache();

builder.Services.AddQertumAuthorization();

builder.Services.AddApiRateLimiting();

var app = builder.Build();

Qertum.ServiceDefaults.InsecureTransport.WarnIfPlainHttp(
    app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Qertum.Transport"),
    app.Environment, "ApiService", identityOptions.Authority);

// Validate the enrollment display URLs now, so a misconfigured value is logged at startup
// rather than on the first wizard load.
app.Services.GetRequiredService<Qertum.Services.Enrollment.EnrollmentDisplayUrls>();

app.Logger.LogInformation(
    "Validating bearer tokens issued by {Authority} for audience {Audience}.",
    identityOptions.Authority, identityOptions.Audience);

// Apply EF Core schema on startup.
// In Test environment, EnsureCreated is used instead of Migrate because
// in-memory SQLite has no migration history table.
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
    var startupLogger = scope.ServiceProvider.GetRequiredService<ILogger<CertificateRequestDbContext>>();
    try
    {
        if (app.Environment.IsEnvironment("Test"))
            db.Database.EnsureCreated();
        else
            db.Database.Migrate();
        var missingTables = DatabaseSchemaCheck.MissingTables(db);
        if (missingTables.Count > 0)
        {
            startupLogger.LogCritical(
                "The database migration history is current but the tables {MissingTables} are missing, so this database was made by an older build whose first migration had the same id. Delete the database file and restart (local development: scripts/reset-dev-environment.sh); a database holding data worth keeping needs a restore from a backup of a current image. Path: {DbPath}",
                missingTables, db.Database.GetConnectionString());
            Environment.Exit(1);
        }
        var policy = scope.ServiceProvider.GetRequiredService<IWebhookDestinationPolicyService>();
        var policyOptions = scope.ServiceProvider.GetRequiredService<IOptions<WebhookDestinationPolicyOptions>>().Value;
        policy.ReconcileAsync(policyOptions).GetAwaiter().GetResult();
    }
    catch (Exception ex)
    {
        startupLogger.LogCritical(ex,
            "Database migration failed at startup. Verify the connection string and that the database file is accessible. Path: {DbPath}",
            db.Database.GetConnectionString());
        Environment.Exit(1);
    }
}

// Issuer #1 comes from the CA files, not SQL: register it once the schema exists. Best effort —
// IssuerRegistry retries lazily and falls back to the unregistered legacy CA.
using (var scope = app.Services.CreateScope())
{
    try
    {
        IssuerBootstrap.EnsureLegacyIssuerAsync(
                scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>(),
                scope.ServiceProvider.GetRequiredService<ICertificateGenerator>(),
                scope.ServiceProvider.GetRequiredService<IAuditLogService>(),
                scope.ServiceProvider.GetRequiredService<TimeProvider>(),
                CancellationToken.None)
            .GetAwaiter().GetResult();
    }
    catch (Exception ex)
    {
        app.Logger.LogWarning(ex, "Could not register the existing CA as issuer #1 at startup; it will be retried on first use.");
    }
}

app.UseQertumSecurityHeaders();

// Configure the HTTP request pipeline.
// Errors the framework writes itself (an unmatched route, an authentication challenge, a forbidden
// response) get a problem-details body too, so every error the API returns has one shape.
// Before every other middleware but the security headers, so even a 401, a 429 or an unhandled 500 names the request. Set when the response starts: the
// exception handler clears headers before it writes its body, and a callback registered here survives that.
app.Use(async (context, next) =>
{
    var correlationId = Qertum.Services.CorrelationIds.For(context);
    context.Response.OnStarting(() =>
    {
        context.Response.Headers[Qertum.Services.CorrelationIds.HeaderName] = correlationId;
        return Task.CompletedTask;
    });
    await next();
});

app.UseStatusCodePages();

app.UseExceptionHandler(exHandler =>
{
    exHandler.Run(async ctx =>
    {
        var feature = ctx.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>();
        var ex = feature?.Error;
        ctx.Response.ContentType = "application/problem+json";

        // Carries the violation list so a client can show every failed rule, not only a message.
        // Approval answers 422: the request is valid, the current policy just refuses it.
        if (ex is IssuancePolicyViolationException policyViolation)
        {
            ctx.Response.StatusCode = policyViolation.Stage == PolicyEnforcementStage.Approval ? 422 : 400;
            await ctx.Response.WriteAsJsonAsync(new
            {
                title = "Issuance Policy Violation",
                detail = policyViolation.Message,
                policyName = policyViolation.Decision.PolicyName,
                versionNumber = policyViolation.Decision.VersionNumber,
                violations = policyViolation.Decision.Violations,
                traceId = Qertum.Services.CorrelationIds.For(ctx)
            });
            return;
        }

        if (ex is PqcPolicyViolationException pqcViolation)
        {
            ctx.Response.StatusCode = pqcViolation.Stage == PolicyEnforcementStage.Approval ? 422 : 400;
            await ctx.Response.WriteAsJsonAsync(new { title = "PQC-Only Policy Violation", detail = pqcViolation.Message, traceId = Qertum.Services.CorrelationIds.For(ctx) });
            return;
        }

        (ctx.Response.StatusCode, string title) = ex switch
        {
            NotFoundException                  => (404, "Not Found"),
            InvalidStateTransitionException    => (409, "Invalid State Transition"),
            DuplicateRequestException          => (409, "Duplicate Request"),
            CaNotInitializedException          => (409, "CA Not Initialized"),
            IssuancePolicyConflictException    => (409, "Issuance Policy Conflict"),
            IssuancePolicyInvariantException   => (422, "Issuance Policy Invariant Violation"),
            // A body the framework could not read (broken JSON, an enum name that does not exist) carries its own
            // 4xx; without this it fell through to 500 and looked like a server fault.
            Microsoft.AspNetCore.Http.BadHttpRequestException bad
                                               => (bad.StatusCode, bad.StatusCode == 400 ? "Bad Request" : "Request Rejected"),
            _                                  => (500, "Internal Server Error")
        };
        await ctx.Response.WriteAsJsonAsync(new { title, detail = ex?.Message, traceId = Qertum.Services.CorrelationIds.For(ctx) });
    });
});

if (app.Environment.IsDevelopment())
{
    // Raw OpenAPI JSON at /openapi/v1.json
    app.MapOpenApi();
    // Interactive Scalar UI at /scalar
    app.MapScalarApiReference();
}

app.UseAuthentication();
// Roles seen in bearer tokens feed the roles page's drift flags. Never fails a request.
app.UseMiddleware<Qertum.Services.Auth.ObservedRoleMiddleware>();
app.UseAuthorization();
app.UseQertumStepUp();
app.UseQertumApprovals();
app.UseRateLimiter();

app.MapCustomCaApi();

app.MapDefaultEndpoints();

app.Run();

public class ApiServiceProgram { }
