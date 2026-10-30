using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;

namespace Qertum.Services.Approvals;

/// <summary>When a route in the approval table actually needs an approval.</summary>
public enum ApprovalGate
{
    /// <summary>Every call.</summary>
    Always,

    /// <summary>An administrator downloading a key that is not their own; the owner is never asked, a non-administrator is left to the handler's 403.</summary>
    NonOwnerKeyAccess,

    /// <summary>Only a bulk operation of kind revoke, and only for a caller who may use it.</summary>
    BulkRevokeOnly
}

/// <summary>One gated route.</summary>
/// <param name="Method">HTTP method.</param>
/// <param name="Pattern">The exact route template the endpoint mapping declares.</param>
/// <param name="Operation">The <see cref="ApprovalOperations"/> key.</param>
/// <param name="Gate">When it applies.</param>
public sealed record ApprovalRouteEntry(string Method, string Pattern, string Operation, ApprovalGate Gate);

/// <summary>
/// The operations that need a second person's approval when it is switched on, as the exact route templates the endpoint
/// mappings declare. One list, one place: <c>ApprovalEndpointTests</c> proves every entry is a real endpoint and is
/// also on the step-up table. The target of a route is its <c>{id}</c> value; creating an intermediate has none.
/// </summary>
public static class ApprovalRoutes
{
    /// <summary>Every gated route.</summary>
    public static readonly IReadOnlyList<ApprovalRouteEntry> Gated =
    [
        new("GET", "/v1/certificate-requests/{id:guid}/private-key", ApprovalOperations.KeyExport, ApprovalGate.NonOwnerKeyAccess),
        new("POST", "/v1/certificate-requests/{id:guid}/pfx", ApprovalOperations.PfxExport, ApprovalGate.NonOwnerKeyAccess),
        new("POST", "/v1/issuers/intermediates", ApprovalOperations.IssuerCreateIntermediate, ApprovalGate.Always),
        new("POST", "/v1/issuers/{id:guid}/renew", ApprovalOperations.IssuerRenew, ApprovalGate.Always),
        new("POST", "/v1/issuers/{id:guid}/certificate", ApprovalOperations.IssuerInstallCertificate, ApprovalGate.Always),
        new("POST", "/v1/issuers/{id:guid}/crl", ApprovalOperations.IssuerUploadCrl, ApprovalGate.Always),
        new("POST", "/v1/issuers/{id:guid}/make-default", ApprovalOperations.IssuerMakeDefault, ApprovalGate.Always),
        new("POST", "/v1/issuers/{id:guid}/retire", ApprovalOperations.IssuerRetire, ApprovalGate.Always),
        new("POST", "/v1/issuers/{id:guid}/archive", ApprovalOperations.IssuerArchive, ApprovalGate.Always),
        new("DELETE", "/v1/issuers/{id:guid}", ApprovalOperations.IssuerDelete, ApprovalGate.Always),
        new("GET", "/v1/issuers/{id:guid}/private-key", ApprovalOperations.IssuerKeyExport, ApprovalGate.Always),
        new("POST", "/v1/issuers/{id:guid}/pfx", ApprovalOperations.IssuerPfxExport, ApprovalGate.Always),
        new("POST", "/v1/bulk-operations/{id:guid}/execute", ApprovalOperations.BulkRevoke, ApprovalGate.BulkRevokeOnly),
        new("POST", "/v1/issuance-policies/{id:guid}/publish", ApprovalOperations.PolicyPublish, ApprovalGate.Always)
    ];

    private static readonly Dictionary<string, ApprovalRouteEntry> Index =
        Gated.ToDictionary(e => $"{e.Method} {e.Pattern}", StringComparer.Ordinal);

    /// <summary>The entry for <paramref name="method"/> on <paramref name="rawPattern"/>, or null.</summary>
    public static ApprovalRouteEntry? Find(string method, string? rawPattern) =>
        rawPattern is not null && Index.TryGetValue($"{method.ToUpperInvariant()} {rawPattern}", out var entry) ? entry : null;
}
