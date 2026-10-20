namespace Qertum.Services.Policies;

/// <summary>
/// The IdP roles of the caller submitting a request. Only REST create, update and the create
/// preview pass one; every other path passes null and the requester-role rule is skipped.
/// </summary>
public sealed record RequesterRoles(IReadOnlyCollection<string> Roles)
{
    /// <summary>Admin passes every requester-role rule, as it bypasses RBAC.</summary>
    public bool IsAdmin => Roles.Contains(AppRoles.Admin, StringComparer.OrdinalIgnoreCase);

    public static RequesterRoles From(IEnumerable<string> roles) => new([.. roles]);
}

/// <summary>
/// The single admission test for a policy version's requester roles, shared by the evaluator and
/// the enrollment-options filter so they cannot disagree.
/// </summary>
public static class RequesterRoleRule
{
    public static IReadOnlyList<string> Allowed(IssuancePolicyVersion version) =>
        IssuancePolicyEvaluator.ReadList(version.AllowedRequesterRolesJson);

    /// <summary>
    /// True when the version lists no roles, the requester is admin, or holds a listed role
    /// (ignoring case). <paramref name="matchedRole"/> is the listed role that matched, else null.
    /// </summary>
    public static bool Admits(IssuancePolicyVersion version, RequesterRoles requester, out string? matchedRole)
    {
        matchedRole = null;
        var allowed = Allowed(version);
        if (allowed.Count == 0 || requester.IsAdmin) return true;

        matchedRole = allowed.FirstOrDefault(a => requester.Roles.Contains(a, StringComparer.OrdinalIgnoreCase));
        return matchedRole is not null;
    }
}
