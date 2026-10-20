namespace Qertum.Web;

/// <summary>The <c>Automation</c> section: what the "Automation snippets" folds print for a pipeline.</summary>
public sealed class AutomationOptions
{
    /// <summary>Name of the configuration section.</summary>
    public const string SectionName = "Automation";

    /// <summary>
    /// Public base URL of the API service as a pipeline reaches it. Display only. The Web host talks to the API
    /// through service discovery, which names no address a CI runner can use, so a deployment states its own;
    /// empty prints the <c>&lt;api-url&gt;</c> blank.
    /// </summary>
    public string ApiUrl { get; set; } = string.Empty;

    /// <summary>True when <see cref="ApiUrl"/> is empty or an absolute http(s) URL.</summary>
    public static bool IsValid(AutomationOptions options) =>
        options.ApiUrl.Length == 0
        || (Uri.TryCreate(options.ApiUrl, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https");
}
