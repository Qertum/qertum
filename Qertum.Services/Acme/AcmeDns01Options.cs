namespace Qertum.Services.Acme;

/// <summary>Configuration for the dns-01 challenge, bound from the "Acme:Dns01" section.</summary>
public sealed class AcmeDns01Options
{
    public const string SectionName = "Acme:Dns01";

    /// <summary>
    /// When false, dns-01 is not offered on new authorizations and wildcard identifiers are
    /// rejected at new-order — a wildcard can only be validated by dns-01, so accepting one with
    /// dns-01 disabled would create an order that can never become valid.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Recursive resolvers to query, as "address" or "address:port" (port defaults to 53). Empty
    /// means the operating system's configured resolvers.
    /// </summary>
    public string[] Resolvers { get; set; } = [];

    public int QueryTimeoutSeconds { get; set; } = 5;
}
