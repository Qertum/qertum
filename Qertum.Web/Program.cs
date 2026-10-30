using Qertum.Web;
using Qertum.Services;
using Qertum.Web.Auth;
using Qertum.Web.Components;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add service defaults & Aspire client integrations.
builder.AddServiceDefaults();

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddHttpContextAccessor();
builder.Services.AddSingleton<OidcTokenClient>();
builder.Services.AddSingleton<CookieRoleRevalidator>();
builder.Services.AddSingleton<MeAccessClient>();
builder.Services.AddScoped<CircuitTokenAccessor>();
builder.Services.AddScoped<ICircuitTokens>(sp => sp.GetRequiredService<CircuitTokenAccessor>());
builder.Services.AddScoped<IStepUpNotifier, StepUpNotifier>();
builder.Services.AddScoped<Microsoft.AspNetCore.Components.Authorization.AuthenticationStateProvider,
    PermissionRevalidatingAuthenticationStateProvider>();
builder.Services.AddSingleton<IMeAccess>(sp => sp.GetRequiredService<MeAccessClient>());
builder.Services.Configure<RoleRevalidationOptions>(builder.Configuration.GetSection(RoleRevalidationOptions.SectionName));
builder.Services.AddSingleton<IdentityAuthority>();
builder.Services.AddOptions<AutomationOptions>().BindConfiguration(AutomationOptions.SectionName)
    .Validate(AutomationOptions.IsValid, "Automation:ApiUrl must be empty or an absolute http(s) URL.").ValidateOnStart();
builder.Services.AddCascadingAuthenticationState();

var identityServiceUrl = builder.Configuration.ResolveIdentityServiceAuthority();

builder.Services.AddOptions<OidcMetadataOptions>().BindConfiguration(OidcMetadataOptions.SectionName).ValidateOnStart();
// Outside Development, plain-HTTP metadata is allowed only when a deployment opts in explicitly.
builder.Services.AddOptions<Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme)
    .PostConfigure<Microsoft.Extensions.Options.IOptions<OidcMetadataOptions>>((options, metadata) =>
    {
        if (!metadata.Value.RequireHttpsMetadata)
            options.RequireHttpsMetadata = false;
    });

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
        options.Events.OnSigningIn = ctx =>
            ctx.HttpContext.RequestServices.GetRequiredService<CookieRoleRevalidator>().OnSigningInAsync(ctx);
        options.Events.OnValidatePrincipal = ctx =>
            ctx.HttpContext.RequestServices.GetRequiredService<CookieRoleRevalidator>().ValidatePrincipalAsync(ctx);
    })
    .AddOpenIdConnect(options =>
    {
        options.Authority = identityServiceUrl;
        options.ClientId = "qertum-web";
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.UsePkce = true;
        // No x-client-SKU / x-client-ver on the authorize redirect: the library version is nobody else's business.
        options.DisableTelemetry = true;
        options.SaveTokens = true;
        options.GetClaimsFromUserInfoEndpoint = true;
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        options.Scope.Add("roles");
        options.Scope.Add("offline_access");
        options.Scope.Add("qertum-api");
        options.TokenValidationParameters.NameClaimType = "name";
        options.TokenValidationParameters.RoleClaimType = "role";
        options.MapInboundClaims = false;

        // Step-up: a challenge from the API makes /auth/step-up ask the identity provider for the authentication class
        // and maximum age it demanded.
        options.Events.OnRedirectToIdentityProvider = context =>
        {
            StepUpRedirect.Apply(context);
            return Task.CompletedTask;
        };

        // Allow OIDC metadata over plain HTTP in Development or when explicitly opted in
        // (single-container deployments where the identity authority is reached over HTTP).
        if (builder.Environment.IsDevelopment())
            options.RequireHttpsMetadata = false;
    });

builder.Services.AddQertumWebAuthorization();

// Server-side API client (with bearer token via AccessTokenHandler)
builder.Services.AddQertumWebApiClient();

// Plain client for reading the caller's access with an explicitly supplied bearer token.
builder.Services.AddHttpClient(MeAccessClient.HttpClientName, (serviceProvider, client) =>
{
    client.BaseAddress = WebApiClientRegistration.ResolveApiBaseUrl(serviceProvider.GetRequiredService<IConfiguration>());
});

// Dedicated plain client for OIDC token-refresh backchannel calls — no AccessTokenHandler to avoid recursion.
builder.Services.AddHttpClient(OidcTokenClient.HttpClientName);

// The request wizard debounces its policy preview on this clock, so tests can drive time.
builder.Services.TryAddSingleton(TimeProvider.System);

builder.Services.AddOutputCache();

var app = builder.Build();

Qertum.ServiceDefaults.InsecureTransport.WarnIfPlainHttp(
    app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Qertum.Transport"),
    app.Environment, "Web", identityServiceUrl);

app.UseQertumSecurityHeaders(SecurityHeaders.WebPolicy(identityServiceUrl));

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
    app.UseHttpsRedirection();
}

app.UseAuthentication();
app.UseAuthorization();

app.UseAntiforgery();

app.UseOutputCache();

app.MapStaticAssets();

// Sign-out endpoint — triggers OIDC front-channel logout.
app.MapGet("/signout", async ctx =>
{
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
});

// Step-up: send a signed-in user through one more authorization request that asks the identity provider for the
// authentication class and maximum age the API demanded. The tokens in the response replace the old ones (never a refresh,
// which keeps the old auth_time). Unsafe input falls back to a plain page rather than being passed on.
app.MapGet("/auth/step-up", (string? returnUrl, string? acr_values, int? max_age, TimeProvider clock) =>
{
    // The marker on the way back lets MainLayout tell "the provider just failed to satisfy this" from a new challenge, which ends a loop.
    var properties = new AuthenticationProperties
    {
        RedirectUri = StepUpRedirect.WithMarker(StepUpRedirect.IsSafeReturnUrl(returnUrl) ? returnUrl! : "/", clock.GetUtcNow())
    };
    if (StepUpRedirect.IsAcceptableAcrValues(acr_values))
        properties.Items[StepUpRedirect.AcrItem] = acr_values;
    if (StepUpRedirect.IsAcceptableMaxAge(max_age))
        properties.Items[StepUpRedirect.MaxAgeItem] = max_age!.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
    return Results.Challenge(properties, [OpenIdConnectDefaults.AuthenticationScheme]);
}).RequireAuthorization();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapDefaultEndpoints();

app.Run();
