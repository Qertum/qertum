using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Qertum.Tests;

/// <summary>
/// A test host configured in one step. <c>new WebApplicationFactory&lt;T&gt;().WithWebHostBuilder(configure)</c> builds the
/// same host but leaves its parent factory behind, created and never disposed; this one has no parent, so disposing
/// the returned factory releases everything it made.
/// </summary>
internal static class ConfiguredFactory
{
    public static WebApplicationFactory<TEntryPoint> Create<TEntryPoint>(Action<IWebHostBuilder> configure)
        where TEntryPoint : class => new Factory<TEntryPoint>(configure);

    private sealed class Factory<TEntryPoint>(Action<IWebHostBuilder> configure) : WebApplicationFactory<TEntryPoint>
        where TEntryPoint : class
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder) => configure(builder);
    }
}
