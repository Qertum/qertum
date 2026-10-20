using Microsoft.Extensions.Http.Resilience;
using Polly;

namespace Microsoft.Extensions.Hosting;

/// <summary>
/// Lets a single request opt out of the standard resilience handler's retries — for a GET the server
/// audits, where a retry would record one look as several.
/// </summary>
public static class HttpRetryOptOut
{
    /// <summary>Request option name; a request carrying it as <c>true</c> is sent once.</summary>
    public const string OptionName = "Qertum.NoRetry";

    private static readonly HttpRequestOptionsKey<bool> Key = new(OptionName);

    /// <summary>Wraps the retry predicate so opted-out requests are never retried.</summary>
    public static void Apply(HttpStandardResilienceOptions options)
    {
        var shouldHandle = options.Retry.ShouldHandle;
        options.Retry.ShouldHandle = args =>
            // The request comes from the resilience context, so a timeout (no response) is covered too.
            args.Context.GetRequestMessage()?.Options.TryGetValue(Key, out var noRetry) == true && noRetry
                ? ValueTask.FromResult(false)
                : shouldHandle(args);
    }
}
