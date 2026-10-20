using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Qertum.Web;
using Qertum.Web.Auth;

namespace Qertum.Tests.Web;

/// <summary>What the pages that carry the "Automation snippets" fold need besides their API client.</summary>
internal static class AutomationTestServices
{
    public static IServiceCollection AddAutomationSnippets(this IServiceCollection services)
    {
        services.AddSingleton(Options.Create(new AutomationOptions()));
        services.AddSingleton(new IdentityAuthority(new ConfigurationBuilder().Build()));
        return services;
    }
}
