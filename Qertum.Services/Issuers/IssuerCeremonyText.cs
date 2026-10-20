namespace Qertum.Services.Issuers;

/// <summary>Human-readable summaries shared by the server's audit details and the offline <c>qca root</c> prompts.</summary>
public static class IssuerCeremonyText
{
    public static string Describe(SubordinateCaProfile p) =>
        $"pathLen={(p.PathLength?.ToString() ?? "none")}; permitted DNS=[{string.Join(", ", p.PermittedDnsSuffixes)}]; " +
        $"excluded DNS=[{string.Join(", ", p.ExcludedDnsSuffixes)}]; permitted IP=[{string.Join(", ", p.PermittedIpRanges)}]; " +
        $"excluded IP=[{string.Join(", ", p.ExcludedIpRanges)}].";
}
