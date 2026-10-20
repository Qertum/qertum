using System.Text.Json;

namespace Qertum.ServiceDefaults.Secrets;

/// <summary>
/// Reads/writes which <see cref="SecretStorageProvider"/> a data directory uses, as a plain JSON
/// file read via direct file I/O — this has to work before any DI container or
/// <c>IConfiguration</c> binder exists, since provider selection happens while building the
/// Data Protection pipeline (ApiService/QueueConsumer/AcmeService) or inside OpenIddict's
/// synchronous <c>AddServer(options =&gt; ...)</c> callback (IdentityService).
/// </summary>
public static class SecretStorageConfig
{
    private const string FileName = "secret-storage.json";

    private sealed record ConfigFile(string Provider);

    /// <summary>
    /// Returns the configured provider, or <see cref="SecretStorageProvider.LocalFileKey"/> when
    /// no config file exists yet — a fresh install must work with zero operator action.
    /// </summary>
    public static SecretStorageProvider Read(string dataDirectory)
    {
        var path = Path.Combine(dataDirectory, FileName);
        if (!File.Exists(path))
            return SecretStorageProvider.LocalFileKey;

        var json = File.ReadAllText(path);
        var config = JsonSerializer.Deserialize<ConfigFile>(json)
            ?? throw new InvalidOperationException($"'{path}' could not be parsed.");

        return Enum.Parse<SecretStorageProvider>(config.Provider);
    }

    public static void Write(string dataDirectory, SecretStorageProvider provider)
    {
        Directory.CreateDirectory(dataDirectory);
        var path = Path.Combine(dataDirectory, FileName);
        var json = JsonSerializer.Serialize(new ConfigFile(provider.ToString()));
        File.WriteAllText(path, json);
    }
}
