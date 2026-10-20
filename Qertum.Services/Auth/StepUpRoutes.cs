namespace Qertum.Services.Auth;

/// <summary>
/// The operations that need step-up when it is enabled, as the exact route templates the endpoint mappings declare.
/// One list, one place: a new sensitive route is one line here. <c>StepUpEndpointTests</c> proves every entry is a real endpoint.
/// </summary>
public static class StepUpRoutes
{
    /// <summary>HTTP method and route template of every protected operation.</summary>
    public static readonly IReadOnlyList<(string Method, string Pattern)> Protected =
    [
        ("GET", "/v1/certificate-requests/{id:guid}/private-key"),
        ("POST", "/v1/certificate-requests/{id:guid}/pfx"),
        ("POST", "/v1/ca/generate"),
        ("POST", "/v1/ca/import"),
        ("POST", "/v1/issuers/intermediates"),
        ("POST", "/v1/issuers/{id:guid}/certificate"),
        ("POST", "/v1/issuers/{id:guid}/crl"),
        ("POST", "/v1/issuers/{id:guid}/make-default"),
        ("POST", "/v1/issuers/{id:guid}/retire"),
        ("POST", "/v1/issuers/{id:guid}/archive"),
        ("DELETE", "/v1/issuers/{id:guid}"),
        ("GET", "/v1/issuers/{id:guid}/private-key"),
        ("POST", "/v1/issuers/{id:guid}/pfx"),
        ("POST", "/v1/bulk-operations/{id:guid}/execute"),
        ("POST", "/v1/secret-storage/migrate"),
        ("PUT", "/v1/permissions/{role}"),
        ("POST", "/v1/permissions/{role}/rename"),
        ("POST", "/v1/issuance-policies/{id:guid}/publish"),
        ("POST", "/v1/approvals/{id:guid}/approve"),
        ("POST", "/v1/approvals/{id:guid}/deny"),
        ("PUT", "/v1/settings/two-person-approval")
    ];

    private static readonly HashSet<string> Keys =
        Protected.Select(p => Key(p.Method, p.Pattern)).ToHashSet(StringComparer.Ordinal);

    /// <summary>True when <paramref name="method"/> on <paramref name="rawPattern"/> (the endpoint's route template) is protected.</summary>
    public static bool IsProtected(string method, string? rawPattern) =>
        rawPattern is not null && Keys.Contains(Key(method, rawPattern));

    private static string Key(string method, string pattern) => $"{method.ToUpperInvariant()} {pattern}";
}
