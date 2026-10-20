using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Services.Recovery;

// Opens a restored /data directly (no host, no network listener, no hosted service) and checks that it works.
// Exit: 0 every check passed or had nothing to test, 1 a check failed, 2 could not test.
if (args.Length != 1)
{
    Console.Error.WriteLine("usage: Qertum.RestoreCheck <data-directory>");
    return 2;
}

var databasePath = Path.Combine(Path.GetFullPath(args[0]), "certificate-requests.db");
if (!File.Exists(databasePath))
{
    Console.WriteLine("check database not-testable no certificate-requests.db under the data directory");
    return 2;
}

try
{
    var services = new ServiceCollection();
    services.AddLogging();
    services.AddSingleton<IConfiguration>(new ConfigurationBuilder().Build());
    // The hosts register the shared cache themselves; the check caches nothing, so a private in-memory one serves.
    services.AddDistributedMemoryCache();
    services.AddCustomCaServices($"Data Source={databasePath}");
    services.AddScoped<RestoreUsabilityChecker>();

    await using var provider = services.BuildServiceProvider();
    await using var scope = provider.CreateAsyncScope();
    var report = await scope.ServiceProvider.GetRequiredService<RestoreUsabilityChecker>().RunAsync();
    foreach (var line in report.Lines)
        Console.WriteLine(line);
    return report.ExitCode;
}
catch (Exception ex) when (ex is not OperationCanceledException)
{
    // A secret store the container cannot reach (TPM, vault) or a data directory that cannot be opened at all:
    // nothing can be said about the backup.
    Console.WriteLine($"check startup not-testable {ex.GetType().Name}: the restored data could not be opened");
    return 2;
}
