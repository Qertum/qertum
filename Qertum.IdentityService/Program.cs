using Qertum.IdentityService.Configuration;
using Qertum.IdentityService.Data;
using Qertum.IdentityService.Models;
using Qertum.IdentityService.Filters;
using Qertum.IdentityService.Services;
using Qertum.IdentityService.Services.Admin;
using Qertum.IdentityService.Services.Audit;
using Qertum.IdentityService.Stores;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Abstractions;
using OpenIddict.Server;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

// All IdP-owned state — users.json, clients.json, identity.db, keys/ — lives under one
// configured directory. Deployments mount a volume there; the base-directory fallback only
// exists so a bare `dotnet run` works.
var identityOptions = new IdentityServiceOptions();
builder.Configuration.GetSection(IdentityServiceOptions.SectionName).Bind(identityOptions);
identityOptions.Validate(builder.Environment.IsDevelopment());
builder.Services.AddSingleton(identityOptions);

var dataPath = identityOptions.ResolveDataPath();

// Before anything reads keys/: a changed IdentityService:SecretStorageProvider re-encrypts them
// here, and the OpenIddict setup below then resolves the protector from the recorded provider.
var secretStorageChange = IdentitySecretStorageMigration.Apply(
    dataPath, identityOptions.SecretStorageProvider,
    provider => Qertum.ServiceDefaults.Secrets.SecretProtectorFactory.Create(dataPath, provider));

// Override by setting ConnectionStrings:Identity in appsettings.json or via environment variable.
var identityConnectionString =
    builder.Configuration.GetConnectionString("Identity") ??
    $"Data Source={Path.Combine(dataPath, "identity.db")}";
builder.Services.AddDbContext<AuthDbContext>(options =>
{
    options.UseSqlite(identityConnectionString);
    options.UseOpenIddict();
});

builder.Services.AddMemoryCache();
builder.AddQertumDistributedCache();
builder.Services.AddSingleton<IPasswordAttemptLimiter, PasswordAttemptLimiter>();

// Tests replace the clock to expire step-up without waiting.
builder.Services.TryAddSingleton(TimeProvider.System);

builder.Services.AddSingleton(sp => new JsonUserStore(
    sp.GetRequiredService<ILogger<JsonUserStore>>(), dataPath, identityOptions.SeedAdminPassword,
    identityOptions.SeedAdminPasswordMustChange));
builder.Services.AddSingleton(new JsonRoleStore(dataPath));
// The audit file sits under the data path so a mounted volume keeps it; Enabled=false writes nothing.
var auditLogPath = identityOptions.AuditLog.Enabled ? identityOptions.ResolveAuditLogPath() : null;
builder.Services.AddSingleton<IIdentityAuditLog>(sp =>
    new IdentityAuditLog(auditLogPath, sp.GetRequiredService<ILogger<IdentityAuditLog>>()));
builder.Services.AddSingleton(sp => new IdentityAuditLogReader(auditLogPath, sp.GetService<TimeProvider>()));
builder.Services.AddSingleton<IGrantRevoker, OpenIddictGrantRevoker>();
builder.Services.AddSingleton<UserAdministrationService>();

// Page input validators (FluentValidation, the method Qertum.Services uses).
builder.Services.AddSingleton<FluentValidation.IValidator<Qertum.IdentityService.Pages.LoginModel.InputModel>, Qertum.IdentityService.Validators.LoginInputValidator>();
builder.Services.AddSingleton<FluentValidation.IValidator<Qertum.IdentityService.Pages.Account.IndexModel.InputModel>, Qertum.IdentityService.Validators.ProfileInputValidator>();
builder.Services.AddSingleton<FluentValidation.IValidator<Qertum.IdentityService.Pages.Account.ChangePasswordModel.InputModel>, Qertum.IdentityService.Validators.ChangePasswordInputValidator>();
builder.Services.AddSingleton<FluentValidation.IValidator<Qertum.IdentityService.Pages.Admin.Users.NewModel.InputModel>, Qertum.IdentityService.Validators.NewUserInputValidator>();
builder.Services.AddSingleton(sp => new JsonClientStore(
    sp.GetRequiredService<ILogger<JsonClientStore>>(),
    sp.GetRequiredService<IHostApplicationLifetime>(),
    identityOptions,
    dataPath));
builder.Services.AddHostedService<ClientSeedHostedService>();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.LogoutPath = "/connect/logout";
        options.SlidingExpiration = true;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        // Re-reads the user on every request, so a role change, disable or deletion reaches a
        // live session immediately instead of after the cookie expires.
        options.Events.OnValidatePrincipal = CookieSession.ValidateAsync;
        // An authenticated caller without the admin role gets a plain 403 on /Admin, not a redirect
        // to an access-denied page this app does not have.
        options.Events.OnRedirectToAccessDenied = context =>
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        };
    });

builder.Services.AddAuthorization(options =>
    options.AddPolicy(AdminAuthorization.PolicyName, policy => policy.RequireRole(RoleDefinition.AdminRoleName)));

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
            .UseDbContext<AuthDbContext>();
    })
    .AddServer(options =>
    {
        // Explicit issuer: the "iss" claim and the discovery document's "issuer" field are
        // pinned here rather than inferred per request, and must match consumers'
        // Identity:Authority. Note this pins only the issuer — OpenIddict still builds every
        // advertised endpoint URL from the incoming request's scheme/host, so a reverse proxy
        // must forward those (see deploy/identity/README.md).
        if (!string.IsNullOrEmpty(identityOptions.Authority))
            options.SetIssuer(new Uri(identityOptions.Authority));

        options.SetAuthorizationEndpointUris("connect/authorize")
               .SetTokenEndpointUris("connect/token")
               .SetEndSessionEndpointUris("connect/logout")
               .SetUserInfoEndpointUris("connect/userinfo")
               .SetIntrospectionEndpointUris("connect/introspect")
               // Advertised so `qca auth logout` can actually revoke the refresh token it
               // holds: OidcLogin.RevokeAsync reads revocation_endpoint from discovery and skips
               // revocation silently when it is absent, which left logged-out tokens usable until
               // they expired. Handled natively by OpenIddict — no passthrough.
               .SetRevocationEndpointUris("connect/revoke")
               .SetDeviceAuthorizationEndpointUris("connect/device_authorization")
               .SetEndUserVerificationEndpointUris("connect/verify");

        options.AllowAuthorizationCodeFlow()
               .AllowRefreshTokenFlow()
               .AllowClientCredentialsFlow()
               .AllowDeviceAuthorizationFlow()
               .RequireProofKeyForCodeExchange();

        options.RegisterScopes(
            OpenIddictConstants.Scopes.Email,
            OpenIddictConstants.Scopes.Profile,
            OpenIddictConstants.Scopes.Roles,
            OpenIddictConstants.Scopes.OfflineAccess,
            "qertum-api");

        // Signing and encryption certificates are registered by IdentityCertificateOptionsSetup
        // (keys/ under the data path, every still-valid certificate, newest first), and
        // IdentityCertificateRotationService reloads them while running when a replacement is
        // due or a key expires.

        // Issue plain JWT access tokens (no encryption) so resource servers can validate without decrypting.
        options.DisableAccessTokenEncryption();

        var aspNetCoreOptions = options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableEndSessionEndpointPassthrough()
               .EnableUserInfoEndpointPassthrough()
               .EnableEndUserVerificationEndpointPassthrough();

        // Disable OpenIddict's HTTPS transport requirement when running in Development or when
        // explicitly opted in (e.g. single-container deployments fronted by plain-HTTP port
        // exposure, where TLS is terminated elsewhere or not used on a trusted LAN).
        if (builder.Environment.IsDevelopment() || identityOptions.DisableTransportSecurity)
            aspNetCoreOptions.DisableTransportSecurityRequirement();

        // Replace OpenIddict's default blank response with a branded "you can close this window" page.
        options.AddEventHandler<OpenIddictServerEvents.ApplyEndUserVerificationResponseContext>(eventBuilder =>
            eventBuilder.UseInlineHandler(context =>
            {
                var httpRequest = context.Transaction.GetHttpRequest();
                if (httpRequest is null) return default;

                var approved = string.IsNullOrEmpty(context.Error);
                httpRequest.HttpContext.Response.ContentType = "text/html; charset=utf-8";
                context.HandleRequest();
                return new ValueTask(httpRequest.HttpContext.Response.WriteAsync(
                    approved ? DeviceAuthorizedHtml() : DeviceDeniedHtml()));
            }));
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

// Keys persisted under the configured data path so restarts don't invalidate issued tokens.
builder.Services.AddSingleton(sp => new IdentityCertificateSource(
    Path.Combine(dataPath, "keys"), identityOptions,
    Qertum.ServiceDefaults.Secrets.SecretProtectorFactory.Create(dataPath), sp.GetRequiredService<TimeProvider>()));
builder.Services.AddSingleton<Microsoft.Extensions.Options.IConfigureOptions<OpenIddictServerOptions>, IdentityCertificateOptionsSetup>();
builder.Services.AddSingleton<IdentityCertificateRotationService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<IdentityCertificateRotationService>());

builder.Services.AddSingleton<ForcedPasswordChangeFilter>();
builder.Services.AddSingleton<StepUpFilter>();
builder.Services.AddRazorPages(options =>
{
    options.Conventions.AuthorizeFolder("/Account");

    // Every admin page is authorized here, once, by folder — never per page — so a page added under
    // /Admin later cannot be left unprotected.
    options.Conventions.AuthorizeFolder("/Admin", AdminAuthorization.PolicyName);

    // Enforce the forced password change on the cookie session itself, for every Razor Page,
    // not just the token-issuing endpoints. Without this a flagged account could sign in with
    // the well-known bootstrap password and use /Admin/Users to mint an unflagged admin.
    // Applying it as a page convention (rather than per handler) means any page added later —
    // under /Account or anywhere else — is covered automatically. Controllers are untouched, so
    // AuthorizationController keeps owning the /connect/* responses.
    options.Conventions.ConfigureFilter(new ServiceFilterAttribute(typeof(ForcedPasswordChangeFilter)));

    // Step-up for the admin folder. Order = 1 runs it after the forced password change (Order 0).
    options.Conventions.AddFolderApplicationModelConvention("/Admin",
        model => model.Filters.Add(new ServiceFilterAttribute(typeof(StepUpFilter)) { Order = 1 }));
});
builder.Services.AddControllers();

var app = builder.Build();

await using (var scope = app.Services.CreateAsyncScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    await db.Database.EnsureCreatedAsync();
}

// Ensure JSON stores seed their files on first run (constructors write defaults).
_ = app.Services.GetRequiredService<JsonUserStore>();
_ = app.Services.GetRequiredService<JsonRoleStore>();
_ = app.Services.GetRequiredService<JsonClientStore>();

if (secretStorageChange is not null)
{
    app.Services.GetRequiredService<IIdentityAuditLog>().Write(
        IdentityAuditActions.SecretStorageMigrated, "IdentityService:SecretStorageProvider",
        detail: $"{secretStorageChange.From} -> {secretStorageChange.To}");
}

// MapStaticAssets (not UseStaticFiles) so identity.css is served build-time compressed
// (gzip on build, brotli on publish) and fingerprinted with immutable cache headers.
app.MapStaticAssets();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages().WithStaticAssets();
app.MapControllers();
app.MapDefaultEndpoints();

app.Run();

static string DeviceAuthorizedHtml() =>
    """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Device Authorized · Qertum IDM</title>
        <link rel="stylesheet" href="/identity.css" />
    </head>
    <body class="centered">
        <main class="shell-main">
            <div class="card">
                <a class="card-brand" href="/">
                    <span class="brand-mark" aria-hidden="true"></span>
                    <span class="brand-text">
                        <span class="brand-name">Custom<em>CA</em></span>
                        <span class="brand-sub">Identity</span>
                    </span>
                </a>
                <div class="signout-ok">
                    <div class="signout-icon">
                        <span class="bi bi-check-circle-fill"></span>
                    </div>
                    <h1>Device <em>Authorized</em></h1>
                    <p class="card-sub">Access granted. You may close this window.</p>
                </div>
            </div>
        </main>
    </body>
    </html>
    """;

static string DeviceDeniedHtml() =>
    """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Access Denied · Qertum IDM</title>
        <link rel="stylesheet" href="/identity.css" />
    </head>
    <body class="centered">
        <main class="shell-main">
            <div class="card">
                <a class="card-brand" href="/">
                    <span class="brand-mark" aria-hidden="true"></span>
                    <span class="brand-text">
                        <span class="brand-name">Custom<em>CA</em></span>
                        <span class="brand-sub">Identity</span>
                    </span>
                </a>
                <div class="signout-ok">
                    <div class="signout-icon" style="background:rgba(var(--error),0.12);border-color:rgba(var(--error),0.25);color:var(--accent-rose)">
                        <span class="bi bi-x-circle-fill"></span>
                    </div>
                    <h1>Access <em>Denied</em></h1>
                    <p class="card-sub">The authorization request was declined. You may close this window.</p>
                </div>
            </div>
        </main>
    </body>
    </html>
    """;

/// <summary>
/// Entry point marker for WebApplicationFactory-based tests. Mirrors ApiServiceProgram.
/// </summary>
public class IdentityServiceProgram { }
