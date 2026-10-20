using System.Text.Json.Serialization;

namespace Qertum.Services;

/// <summary>How webhook destinations with public IP addresses are selected.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum WebhookPublicMode
{
    /// <summary>Allow any public HTTP or HTTPS destination.</summary>
    AnyPublic,

    /// <summary>Allow only listed public origins.</summary>
    ListedPublic
}

/// <summary>The address class an exact webhook destination rule permits.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum WebhookDestinationRuleKind
{
    /// <summary>An exact origin whose DNS answers must all be public.</summary>
    Public,

    /// <summary>An exact origin whose DNS answers must match its pinned IP addresses.</summary>
    Internal
}
