// Configure the Aspire distributed application host that coordinates all project resources.
var builder = DistributedApplication.CreateBuilder(args);

// Store certificate request data in a local SQLite database.
// Override by setting ConnectionStrings:CertificateRequests in appsettings.json or via environment variable.
var certificateRequestsConnectionString =
    builder.Configuration["ConnectionStrings:CertificateRequests"] ??
    $"Data Source={Path.Combine(AppContext.BaseDirectory, "certificate-requests.db")}";

// Shared cache. The CRL and ACME nonces live here, and both are wrong when cached per process:
// two API instances would publish independently-generated CRLs, and a nonce minted by one ACME
// instance would be unknown to the next. Runs as a container, so local runs need Docker.
var cache = builder.AddRedis("cache");

// Deterministic secret for the IdentityService's own client seeding. The API service no
// longer needs it: bearer tokens are validated locally against JWKS, not by introspection.
const string aspireApiClientSecret = "aspire-dev-api-introspection-secret";

// Identity provider — OpenIddict-backed IDM. Browser-reachable via service discovery URL.
// Its data path is pinned beside the AppHost binaries so local runs and the integration
// tests share one users.json/clients.json/identity.db across restarts.
var identityService = builder.AddProject<Projects.Qertum_IdentityService>("identityservice")
    .WithExternalHttpEndpoints()
    .WithEnvironment("IdentityService__ApiClientSecret", aspireApiClientSecret)
    .WithEnvironment("IdentityService__DataPath",
        Path.Combine(AppContext.BaseDirectory, "identity-data"))
    .WithReference(cache)
    .WaitFor(cache)
    // Aspire assigns the web frontend's port at runtime, so its redirect URIs cannot live in
    // clients.json. Production reads clients.json only; this flag is the dev/test opt-in.
    .WithEnvironment("IdentityService__EnableServiceDiscoveryRedirectUris", "true")
    .WithHttpHealthCheck("/health");

// Register the API service and provide its database connection string and health endpoint.
// The API validates bearer tokens against the identity service's JWKS, so it needs the
// issuer URL but no shared secret.
var apiService = builder.AddProject<Projects.Qertum_ApiService>("apiservice")
    .WithEnvironment("ConnectionStrings__CertificateRequests", certificateRequestsConnectionString)
    .WithReference(identityService)
    .WaitFor(identityService)
    .WithReference(cache)
    .WaitFor(cache)
    .WithHttpHealthCheck("/health");

apiService.WithEnvironment("Identity__Authority", identityService.GetEndpoint("https"));

// Register the queue consumer and delay its startup until the API service is ready.
// The consumer shares the cache so that finalising a revocation can evict the published CRL
// instead of leaving relying parties with a stale one until its TTL runs out.
builder.AddProject<Projects.Qertum_QueueConsumer>("queueconsumer")
    .WithEnvironment("ConnectionStrings__CertificateRequests", certificateRequestsConnectionString)
    .WithReference(cache)
    .WaitFor(cache)
    .WaitFor(apiService);

// ACME server — shares the same SQLite database; waits for ApiService so the DB migration runs first.
var acmeService = builder.AddProject<Projects.Qertum_AcmeService>("acmeservice")
    .WithExternalHttpEndpoints()
    .WithEnvironment("ConnectionStrings__CertificateRequests", certificateRequestsConnectionString)
    .WithReference(cache)
    .WaitFor(cache)
    .WaitFor(apiService)
    .WithHttpHealthCheck("/health");
acmeService.WithEnvironment("Acme__BaseUrl", acmeService.GetEndpoint("https"));

// EST server (RFC 7030) — shares the same SQLite database; independent tier like acmeService,
// not waited-on by the Aspire integration fixture.
var estService = builder.AddProject<Projects.Qertum_EstService>("estservice")
    .WithExternalHttpEndpoints()
    .WithEnvironment("ConnectionStrings__CertificateRequests", certificateRequestsConnectionString)
    .WithReference(cache)
    .WaitFor(cache)
    .WaitFor(apiService)
    .WithHttpHealthCheck("/health");

// Public enrollment URLs the request wizard shows for client-held keys. Display only, and no
// startup dependency: acmeservice and estservice already wait for apiservice.
apiService
    .WithEnvironment("Enrollment__AcmeDirectoryUrl",
        ReferenceExpression.Create($"{acmeService.GetEndpoint("https")}/acme/directory"))
    .WithEnvironment("Enrollment__EstBaseUrl",
        ReferenceExpression.Create($"{estService.GetEndpoint("https")}/.well-known/est"));

// Register the Blazor frontend, expose HTTP endpoints externally, and wire it to the API service.
var webFrontend = builder.AddProject<Projects.Qertum_Web>("webfrontend")
    .WithExternalHttpEndpoints()
    .WithReference(apiService)
    .WithReference(identityService)
    .WaitFor(apiService)
    .WaitFor(identityService)
    // Display only: the address the "Automation snippets" folds print for pipelines.
    .WithEnvironment("Automation__ApiUrl", ReferenceExpression.Create($"{apiService.GetEndpoint("https")}"))
    .WithHttpHealthCheck("/health");

// Inject the web frontend's Aspire-assigned URL into the identity service so that
// ClientSeedHostedService can register the correct redirect URIs at runtime instead
// of relying on hardcoded port numbers in clients.json.
identityService.WithReference(webFrontend);

// Inject the identity service's own HTTPS URL back into itself so it can set an explicit
// issuer on tokens; prevents iss mismatches when tokens are issued via HTTP but validated
// by the ApiService via the HTTPS service-discovery URL.
identityService.WithEnvironment("IdentityService__Authority", identityService.GetEndpoint("https"));

// Build the distributed application model and start all configured projects.
builder.Build().Run();
