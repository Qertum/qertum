using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Qertum.Tests.IdpInterop;

/// <summary>The real ApiService with its real JWT bearer validation, pointed at an external identity provider.</summary>
internal static class IdpApiHost
{
    public static async Task<WebApplicationFactory<ApiServiceProgram>> CreateAsync(string authority, int maxAgeSeconds, CancellationToken ct)
    {
        var database = SharedInMemoryDatabase.Create();
        var factory = new WebApplicationFactory<ApiServiceProgram>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("ASPNETCORE_ENVIRONMENT", "Test");
            builder.UseSetting("Identity:Authority", authority);
            builder.UseSetting("Identity:Audience", "qertum-api");
            builder.UseSetting("Identity:RequireHttpsMetadata", "false");
            builder.UseSetting("Identity:StepUp:Enabled", "true");
            builder.UseSetting("Identity:StepUp:AcrValues", "mfa");
            builder.UseSetting("Identity:StepUp:MaxAgeSeconds", maxAgeSeconds.ToString());
            builder.ConfigureTestServices(services => database.ReplaceDbContext(services));
        });
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        return factory;
    }
}
