namespace Qertum.Services;

/// <summary>Per-request options the API client sets for the host's HTTP pipeline.</summary>
public static class ApiRequestOptions
{
    /// <summary>
    /// Request option name that tells the standard resilience handler not to retry. Mirrors
    /// <c>HttpRetryOptOut.OptionName</c> in ServiceDefaults, which this project does not reference.
    /// </summary>
    public const string NoRetry = "Qertum.NoRetry";

    internal static readonly HttpRequestOptionsKey<bool> NoRetryKey = new(NoRetry);
}
