namespace Qertum.Services.Policies;

/// <summary>
/// Who is acting, for the rules that depend on the actor rather than the request: whether the
/// caller may handle CA-capable templates and whether an approver is the requester. Null means no
/// human caller and the CA rules are skipped (consumer, auto-renewal, internal callers).
/// <see cref="Protocol"/> is ACME or EST: no human approves those requests, so it never holds the permission.
/// </summary>
/// <param name="Subject">Stable IdP subject (<c>sub</c>), null when the identity has none.</param>
/// <param name="Name">Display name the audit trail records (<c>RequestedBy</c> for legacy rows).</param>
/// <param name="IsAdmin">The caller holds the admin role.</param>
/// <param name="HoldsCaPermission">The caller's roles grant <c>certificates.ca</c>.</param>
/// <param name="IsProtocol">The caller is an enrollment protocol, not a person.</param>
public sealed record CallerContext(string? Subject, string Name, bool IsAdmin, bool HoldsCaPermission, bool IsProtocol = false)
{
    /// <summary>ACME and EST enrollment: never admitted for a CA-capable template.</summary>
    public static CallerContext Protocol { get; } = new(null, "protocol", IsAdmin: false, HoldsCaPermission: false, IsProtocol: true);

    /// <summary>Admin bypasses permissions, as everywhere else.</summary>
    public bool MayHandleCaRequests => IsAdmin || HoldsCaPermission;
}

/// <summary>The single admission test for CA-capable templates, shared by the evaluator and the enrollment-options filter.</summary>
public static class CaPermissionRule
{
    /// <summary>True when the template is not CA-capable, or <paramref name="caller"/> may handle CA requests.</summary>
    public static bool Admits(CertificateTemplate? template, CallerContext caller) =>
        !CaCapableTemplate.IsCaCapable(template) || caller.MayHandleCaRequests;
}

/// <summary>Whether an approver is the person who filed the request.</summary>
public static class IndependentApprovalRule
{
    /// <summary>
    /// Subjects compare when the request has one; legacy rows without a subject compare
    /// <c>RequestedBy</c> to the approver's mapped name, as key access does.
    /// </summary>
    public static bool IsSelfApproval(CertificateRequest request, CallerContext approver) =>
        request.RequestedBySubject is { Length: > 0 } owner
            ? approver.Subject is { } subject && string.Equals(owner, subject, StringComparison.Ordinal)
            : string.Equals(request.RequestedBy, approver.Name, StringComparison.Ordinal);
}

/// <summary>Builds a <see cref="CallerContext"/> from already-mapped claims. Takes primitives: only hosts with JWT authentication have an <c>IIdentityClaimsMapper</c>.</summary>
public interface ICallerContextResolver
{
    /// <summary>Resolves the caller's effective permissions from <paramref name="roles"/>.</summary>
    Task<CallerContext> ResolveAsync(string? subject, string name, IReadOnlyCollection<string> roles, CancellationToken cancellationToken = default);
}

internal sealed class CallerContextResolver(IRolePermissionService rolePermissions) : ICallerContextResolver
{
    public async Task<CallerContext> ResolveAsync(string? subject, string name, IReadOnlyCollection<string> roles, CancellationToken cancellationToken = default)
    {
        var isAdmin = roles.Contains(AppRoles.Admin, StringComparer.OrdinalIgnoreCase);
        var holds = isAdmin
            || (await rolePermissions.GetEffectivePermissionsAsync(roles, cancellationToken)).Contains(AppPermissions.CertificatesCa);
        return new CallerContext(subject, name, isAdmin, holds);
    }
}
