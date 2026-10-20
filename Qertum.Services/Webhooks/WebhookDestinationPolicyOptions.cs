using System.Net;
using Microsoft.Extensions.DependencyInjection;

namespace Qertum.Services.Webhooks;

/// <summary>Operator-supplied JSON baseline for webhook destination permissions.</summary>
public sealed class WebhookDestinationPolicyOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "WebhookDestinationPolicy";

    /// <summary>Whether public destinations are open or listed.</summary>
    public WebhookPublicMode PublicMode { get; set; } = WebhookPublicMode.AnyPublic;

    /// <summary>Configuration-owned exact-origin rules.</summary>
    public WebhookDestinationRuleOption[] Rules { get; set; } = [];

    internal static bool IsValid(WebhookDestinationPolicyOptions options)
    {
        if (!Enum.IsDefined(options.PublicMode) || options.Rules is null) return false;
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var rule in options.Rules)
        {
            if (!WebhookDestinationPolicyService.TryNormalize(rule, out var normalized)) return false;
            if (!keys.Add(normalized.StableKey)) return false;
        }
        return true;
    }
}

/// <summary>One exact-origin rule supplied by operator configuration.</summary>
public sealed class WebhookDestinationRuleOption
{
    /// <summary>Public or internal address class.</summary>
    public WebhookDestinationRuleKind Kind { get; set; }

    /// <summary>HTTP or HTTPS scheme.</summary>
    public string Scheme { get; set; } = "https";

    /// <summary>Exact hostname or IP literal.</summary>
    public string Host { get; set; } = "";

    /// <summary>Effective destination port.</summary>
    public int Port { get; set; } = 443;

    /// <summary>Exact allowed IP addresses for an internal origin.</summary>
    public string[] AllowedIpAddresses { get; set; } = [];
}

/// <summary>Registers startup validation for the API host's JSON policy baseline.</summary>
public static class WebhookDestinationPolicyOptionsExtensions
{
    /// <summary>Binds and validates the API host's destination policy section.</summary>
    public static IServiceCollection AddWebhookDestinationPolicyOptions(this IServiceCollection services)
    {
        services.AddOptions<WebhookDestinationPolicyOptions>()
            .BindConfiguration(WebhookDestinationPolicyOptions.SectionName)
            .Validate(WebhookDestinationPolicyOptions.IsValid, "WebhookDestinationPolicy contains an invalid or duplicate rule.")
            .ValidateOnStart();
        return services;
    }
}
