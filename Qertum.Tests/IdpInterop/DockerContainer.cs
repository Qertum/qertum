using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace Qertum.Tests.IdpInterop;

/// <summary>A throwaway container started with <c>docker run</c>, removed on dispose.</summary>
internal sealed class DockerContainer : IAsyncDisposable
{
    private DockerContainer(string name) => Name = name;

    public string Name { get; }

    /// <summary>True when a Docker daemon answers.</summary>
    public static async Task<bool> IsAvailableAsync() => (await RunAsync(TimeSpan.FromSeconds(15), "info")).ExitCode == 0;

    public static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    /// <summary>Starts <paramref name="image"/> publishing <paramref name="containerPort"/> on <paramref name="hostPort"/>.</summary>
    public static async Task<DockerContainer> StartAsync(string image, int hostPort, int containerPort,
        IReadOnlyDictionary<string, string> environment, params string[] arguments)
    {
        var name = "qertum-idp-" + Guid.NewGuid().ToString("N")[..12];
        var args = new List<string> { "run", "-d", "--rm", "--name", name, "-p", $"{hostPort}:{containerPort}" };
        foreach (var (key, value) in environment)
        {
            args.Add("-e");
            args.Add($"{key}={value}");
        }

        args.Add(image);
        args.AddRange(arguments);
        var result = await RunAsync(TimeSpan.FromMinutes(10), [.. args]);
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"docker run {image} failed: {result.Output}");
        return new DockerContainer(name);
    }

    public async ValueTask DisposeAsync() => await RunAsync(TimeSpan.FromSeconds(60), "rm", "-f", Name);

    public async Task<string> LogsAsync() => (await RunAsync(TimeSpan.FromSeconds(30), "logs", Name)).Output;

    private static async Task<(int ExitCode, string Output)> RunAsync(TimeSpan timeout, params string[] arguments)
    {
        var info = new ProcessStartInfo("docker") { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var argument in arguments)
            info.ArgumentList.Add(argument);
        try
        {
            using var process = Process.Start(info)!;
            using var cts = new CancellationTokenSource(timeout);
            var output = process.StandardOutput.ReadToEndAsync(cts.Token);
            var error = process.StandardError.ReadToEndAsync(cts.Token);
            await process.WaitForExitAsync(cts.Token);
            return (process.ExitCode, await output + await error);
        }
        catch (Exception ex) when (ex is OperationCanceledException or System.ComponentModel.Win32Exception)
        {
            return (-1, ex.Message);
        }
    }
}
