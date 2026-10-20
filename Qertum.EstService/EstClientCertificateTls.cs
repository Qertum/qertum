using Microsoft.AspNetCore.Server.Kestrel.Https;

/// <summary>
/// TLS client-certificate handling for <c>/simplereenroll</c>. Kestrel only requests the certificate; whether it is
/// acceptable is decided in <c>EstEndpointMappings</c> (chain to an Active/Retired issuer path, not revoked, CSR identity).
/// </summary>
internal static class EstClientCertificateTls
{
    /// <summary>
    /// Requests, never requires, a client certificate (<c>/simpleenroll</c> and the public routes present none) and
    /// accepts whatever is presented at the handshake. The platform validator would otherwise drop a certificate
    /// whose chain it cannot build (post-quantum and composite issuers, a private root), and re-enrollment would
    /// see no certificate at all.
    /// </summary>
    internal static void Configure(HttpsConnectionAdapterOptions https)
    {
        https.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
        https.ClientCertificateValidation = (_, _, _) => true;
    }
}
