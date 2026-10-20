namespace Qertum.Web.Components.Pages.Enrollment;

using Qertum.Services;

/// <summary>
/// One ready-to-run setup example for an enrollment client.
/// </summary>
/// <param name="Id">Stable identifier, used as the tab key and in tests.</param>
/// <param name="Title">Client name as the operator knows it.</param>
/// <param name="Description">What this example does and when to reach for it.</param>
/// <param name="Language">Syntax hint for the rendered block (<c>bash</c> or <c>yaml</c>).</param>
/// <param name="Command">The example itself, with the deployment's own URLs already substituted.</param>
public sealed record ClientSetupSnippet(string Id, string Title, string Description, string Language, string Command);

/// <summary>
/// Builds the enrollment wizard's copy-paste client examples.
/// </summary>
/// <remarks>
/// Two rules hold for every snippet here, and both are pinned by <c>ClientSetupSnippetTests</c>.
/// First, a snippet carries the deployment's configured URL and nothing else — a deployment behind a
/// proxy publishes its own, and an example naming any other host points the operator's client at
/// something that is not this CA. Second, a snippet never carries a credential: the EAB MAC key is
/// returned once by <c>POST /v1/acme/external-account-keys</c> and is unreadable afterwards, and EST
/// enrollment passwords are equally not ours to hand out, so both appear as angle-bracket blanks.
/// The examples also always verify TLS against the downloaded root rather than reaching for an
/// insecure flag, because the first thing an operator copies is the thing they keep.
/// </remarks>
public static class ClientSetupSnippets
{
    /// <summary>File name the wizard's root-certificate download uses, referenced by every example.</summary>
    public const string RootCertificateFileName = "qertum-root.pem";

    /// <summary>
    /// Installing the downloaded root into the platform trust store. This comes first in the UI:
    /// every client below fails its TLS handshake until it is done.
    /// </summary>
    public static IReadOnlyList<ClientSetupSnippet> TrustBootstrap() =>
    [
        new("linux", "Linux", "Debian and Ubuntu; on RHEL family use /etc/pki/ca-trust/source/anchors and update-ca-trust.", "bash",
            $"""
            sudo cp {RootCertificateFileName} /usr/local/share/ca-certificates/qertum-root.crt
            sudo update-ca-certificates
            """),
        new("macos", "macOS", "Adds the root to the system keychain as a trusted anchor.", "bash",
            $"""
            sudo security add-trusted-cert -d -r trustRoot \
              -k /Library/Keychains/System.keychain {RootCertificateFileName}
            """),
        new("windows", "Windows", "Run in an elevated PowerShell prompt.", "bash",
            $"""
            Import-Certificate -FilePath .\{RootCertificateFileName} `
              -CertStoreLocation Cert:\LocalMachine\Root
            """)
    ];

    /// <summary>Setup examples for the ACME clients the wizard names.</summary>
    /// <param name="route">The ACME route from <c>GET /v1/enrollment/options</c>.</param>
    /// <returns>One snippet per client, in the order the wizard shows them.</returns>
    public static IReadOnlyList<ClientSetupSnippet> ForAcme(AcmeEnrollmentRoute route)
    {
        var directory = route.DirectoryUrl;
        var eab = route.ExternalAccountBindingRequired;

        // certbot only: its argument parser reads a separate word starting with '-' (a base64url MAC key can) as an option.
        var certbotEab = eab
            ? " \\\n  --eab-kid <kid> --eab-hmac-key=<hmac-key>"
            : string.Empty;
        var acmeShEab = eab
            ? " \\\n  --eab-kid <kid> --eab-hmac-key <hmac-key>"
            : string.Empty;

        return
        [
            new("certbot", "certbot",
                "Standalone or webroot enrollment on a single host. Point REQUESTS_CA_BUNDLE at the root so certbot trusts this CA.",
                "bash",
                $"""
                export REQUESTS_CA_BUNDLE=$PWD/{RootCertificateFileName}

                certbot register --server {directory} \
                  --email <you@your-domain> --agree-tos{certbotEab}

                certbot certonly --server {directory} \
                  --standalone -d <your-domain>
                """),

            new("cert-manager", "cert-manager",
                eab
                    ? "Kubernetes. Create the EAB secret first, then the issuer; cert-manager trusts the CA via the root bundle in the same namespace."
                    : "Kubernetes. cert-manager trusts the CA via the root bundle in the same namespace.",
                "yaml",
                BuildCertManager(directory, eab)),

            new("acme.sh", "acme.sh",
                "Shell-only client for appliances and shared hosting where certbot's Python stack is awkward.",
                "bash",
                $"""
                export CA_BUNDLE=$PWD/{RootCertificateFileName}

                acme.sh --register-account --server {directory} \
                  -m <you@your-domain>{acmeShEab}

                acme.sh --issue --server {directory} \
                  -d <your-domain> --standalone
                """)
        ];
    }

    /// <summary>Setup examples for EST enrollment.</summary>
    /// <param name="route">The EST route from <c>GET /v1/enrollment/options</c>.</param>
    /// <returns>One snippet per client, in the order the wizard shows them.</returns>
    public static IReadOnlyList<ClientSetupSnippet> ForEst(EstEnrollmentRoute route)
    {
        var baseUrl = route.BaseUrl.TrimEnd('/');

        return
        [
            new("curl", "curl + openssl",
                "Works anywhere and is the quickest way to prove enrollment end to end. EST carries the CSR and the issued chain as base64 PKCS#7.",
                "bash",
                $"""
                openssl req -new -newkey rsa:2048 -nodes \
                  -keyout device.key -out device.csr -subj "/CN=<your-device>"

                # The CSR goes up base64-encoded, without the PEM header lines.
                openssl req -in device.csr -outform DER | base64 > device.b64

                curl --cacert {RootCertificateFileName} \
                  --user <username>:<password> \
                  --header "Content-Type: application/pkcs10" \
                  --header "Content-Transfer-Encoding: base64" \
                  --data @device.b64 \
                  {baseUrl}/simpleenroll | base64 -d > issued.p7b

                openssl pkcs7 -inform DER -in issued.p7b -print_certs -out device.pem
                """),

            new("estclient", "estclient (libest)",
                "Cisco libest's reference client, the usual native EST client on Linux. Windows has no standard EST client — use the curl example there.",
                "bash",
                $"""
                export EST_OPENSSL_CACERT=$PWD/{RootCertificateFileName}

                estclient -e -s <est-host> -p <est-port> \
                  -o ./enrolled \
                  --common-name <your-device> \
                  -u <username> -h <password>

                # -s/-p must match the EST base URL this deployment publishes:
                # {baseUrl}
                """)
        ];
    }

    private static string BuildCertManager(string directory, bool eab)
    {
        var eabBlock = eab
            ? """
                  externalAccountBinding:
                    keyID: <kid>
                    keySecretRef:
                      name: qertum-eab
                      key: secret

            """
            : string.Empty;

        var eabSecret = eab
            ? """
            # kubectl create secret generic qertum-eab --from-literal=secret='<hmac-key>'

            """
            : string.Empty;

        return $"""
            {eabSecret}# kubectl create configmap qertum-root --from-file={RootCertificateFileName}
            apiVersion: cert-manager.io/v1
            kind: ClusterIssuer
            metadata:
              name: qertum
            spec:
              acme:
                server: {directory}
                email: <you@your-domain>
                privateKeySecretRef:
                  name: qertum-account-key
            {eabBlock}    solvers:
                  - http01:
                      ingress:
                        ingressClassName: nginx
            """;
    }
}
