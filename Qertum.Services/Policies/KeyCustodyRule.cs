namespace Qertum.Services.Policies;

/// <summary>
/// The single admission test for a policy version's key custody, shared by the evaluator and the
/// enrollment-options filter so they cannot disagree.
/// </summary>
public static class KeyCustodyRule
{
    /// <summary>
    /// True when a request whose key the CA generates may issue under <paramref name="version"/>.
    /// False under <see cref="KeyCustodyMode.RequireClientGenerated"/>, which only a CSR-carrying
    /// request satisfies — in practice ACME finalize or EST enrollment.
    /// </summary>
    public static bool AdmitsCaGeneratedKey(IssuancePolicyVersion version) =>
        version.KeyCustody != KeyCustodyMode.RequireClientGenerated;
}
