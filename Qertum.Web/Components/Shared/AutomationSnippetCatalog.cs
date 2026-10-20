namespace Qertum.Web.Components.Shared;

/// <summary>One copy-paste example for repeating a Web UI operation from a pipeline.</summary>
/// <param name="Id">Stable identifier, used in tests and as the element key.</param>
/// <param name="Title">What the example does, as the operator knows it.</param>
/// <param name="Description">When to reach for it, and what it does not cover.</param>
/// <param name="Command">The example, with the deployment's URLs and the page's identifiers substituted.</param>
public sealed record AutomationSnippet(string Id, string Title, string Description, string Command);

/// <summary>The operations a page can offer automation snippets for.</summary>
public enum AutomationOperation
{
    /// <summary>Authenticate a pipeline: the setup every other example assumes.</summary>
    Setup,
    /// <summary>Create a certificate request.</summary>
    Create,
    /// <summary>Approve or deny a pending request.</summary>
    Approve,
    /// <summary>Download the certificate, or its key for the owner.</summary>
    Download,
    /// <summary>Renew an issued certificate.</summary>
    Renew,
    /// <summary>Revoke one certificate.</summary>
    Revoke,
    /// <summary>Preview and run a bulk revoke or renew.</summary>
    Bulk,
    /// <summary>List certificates and export the inventory.</summary>
    Inventory,
    /// <summary>List and create webhook subscriptions.</summary>
    Webhooks,
    /// <summary>Show or set the facts recorded about a certificate.</summary>
    Metadata
}

/// <summary>
/// Builds the "Automation snippets" examples.
/// </summary>
/// <remarks>
/// Rules, pinned by <c>AutomationSnippetTests</c>: every <c>qca</c> line parses against the real command tree (the
/// text cannot drift from the CLI); a snippet carries the deployment's configured URLs and the page's own
/// identifiers and nothing else; credentials are angle-bracket blanks, never values; TLS is never switched off.
/// Where <c>qca</c> has no command (revoking one certificate) the example is the REST call, and says so.
/// </remarks>
public static class AutomationSnippetCatalog
{
    /// <summary>The blank printed when the deployment has not stated a public API URL.</summary>
    public const string ApiUrlBlank = "<api-url>";

    /// <summary>Examples for one operation.</summary>
    /// <param name="operation">What the page lets the operator do.</param>
    /// <param name="apiUrl">Configured public API URL, or empty.</param>
    /// <param name="identityUrl">The identity authority the Web UI signs in against.</param>
    /// <param name="id">The certificate or request the page shows, when it shows one.</param>
    public static IReadOnlyList<AutomationSnippet> For(AutomationOperation operation, string apiUrl, string identityUrl, Guid? id = null)
    {
        var api = apiUrl.Length == 0 ? ApiUrlBlank : apiUrl.TrimEnd('/');
        var target = id?.ToString() ?? "<id>";

        return operation switch
        {
            AutomationOperation.Setup =>
            [
                new("setup", "Authenticate a pipeline",
                    "A service client with the client_credentials grant (created by an administrator in the identity admin area) gets a short-lived token; give it only the roles the job needs. qca checks TLS against the operating system's trust store, so install the root first (Enroll, client setup).",
                    $"""
                    export QERTUM_API_URL={api}
                    export QERTUM_IDENTITY_URL={identityUrl.TrimEnd('/')}
                    TOKEN_ENDPOINT=$(curl -sS --cacert qertum-root.pem {identityUrl.TrimEnd('/')}/.well-known/openid-configuration | jq -r .token_endpoint)
                    export QERTUM_TOKEN=$(curl -sS --cacert qertum-root.pem \
                      --data-urlencode grant_type=client_credentials \
                      --data-urlencode client_id=<client-id> \
                      --data-urlencode client_secret=<client-secret> \
                      --data-urlencode scope=qertum-api \
                      "$TOKEN_ENDPOINT" | jq -r .access_token)
                    """),
                new("failure", "Fail a job with a reference for the report",
                    "Exit codes: 0 success, 1 failed call or refusal, 2 rejected by policy (create --dry-run), 3 timed out while still in progress. On a failed call qca prints a 'correlation id:' line to stderr; quote it in the report, and search the service log for it (the console line carries the same id).",
                    """
                    qca requests approve <request-id> --wait --timeout 120 2>qca-error.log
                    status=$?
                    if [ "$status" -ne 0 ]; then
                      cat qca-error.log >&2
                      grep 'correlation id:' qca-error.log
                      exit "$status"
                    fi
                    """)
            ],
            AutomationOperation.Create =>
            [
                new("create-preview", "Check a request against policy",
                    "Exit 0 allowed, 2 rejected by policy, 1 failed. Run it before the real request in a pipeline.",
                    "qca requests create --common-name <name> --san <name> --type WebServer --dry-run"),
                new("create", "Create the request",
                    "The request starts Pending; it is approved separately, or automatically where the deployment allows it.",
                    "qca requests create --common-name <name> --san <name> --type WebServer")
            ],
            AutomationOperation.Approve =>
            [
                new("approve", "Approve and wait for the certificate",
                    "Exit 0 issued, 1 rejected during issuance or a failed call, 3 timeout while still in progress.",
                    $"qca requests approve {target} --wait --timeout 120"),
                new("deny", "Deny the request", "Changes the request to Rejected.", $"qca requests deny {target}")
            ],
            AutomationOperation.Download =>
            [
                new("download-cert", "Download the certificate",
                    "Formats pem, crt, cer, p7b or pfx; the format must fit the algorithm. Use --out - for stdout.",
                    $"qca cert download-cert {target} --format pem --out cert.pem"),
                new("download-key", "Download the private key (owner or administrator)",
                    "Audited. Write it to a file with tight permissions, never into a log or a pipeline artifact.",
                    $"qca cert download-key {target} --out cert.key")
            ],
            AutomationOperation.Renew =>
            [
                new("renew", "Renew the certificate",
                    "Creates a new request from this certificate's settings; it follows the usual approval path.",
                    $"qca cert renew {target}"),
                new("renew-deploy", "Renew, approve and fetch the new certificate",
                    "A renew-and-deploy job: the renewal is approved by this same job (needs the approve permission, and a CA-capable certificate needs an independent approver), then the new files replace the old ones. Copying them to the service and reloading it is yours to add. The key download needs the job to own the certificate; it does, because a renewal copies its owner.",
                    $"""
                    REQUEST_ID=$(qca cert renew {target} --output json | jq -r .id)
                    qca requests approve "$REQUEST_ID" --wait --timeout 120
                    qca cert download-cert "$REQUEST_ID" --format pem --out cert.pem
                    qca cert download-key "$REQUEST_ID" --out cert.key
                    """)
            ],
            AutomationOperation.Revoke =>
            [
                new("revoke", "Revoke the certificate (REST)",
                    "qca has no single-certificate revoke command; for many certificates use a bulk revoke. Needs certificates.manage. Answers 202 while revocation is pending.",
                    $$"""
                    curl -sS --cacert qertum-root.pem -X POST \
                      -H "Authorization: Bearer $QERTUM_TOKEN" \
                      -H "Content-Type: application/json" \
                      -d '{"reason":"<reason>"}' \
                      {{api}}/v1/certificate-requests/{{target}}/revoke
                    """)
            ],
            AutomationOperation.Bulk =>
            [
                new("bulk-renew", "Renew everything expiring soon",
                    "The first command only previews: it prints the count and the exclusions. Execute with the printed count; execute does nothing if the count changed.",
                    """
                    qca bulk renew --expires-within 30
                    qca bulk execute <operation-id> --confirm-count <count> --wait
                    """),
                new("bulk-revoke", "Revoke by criteria",
                    "Same two steps; a reason is required. Criteria are --issuer, --template, --owner, --expires-within and --cn, or --all.",
                    """
                    qca bulk revoke --issuer <issuer-id> --reason <reason>
                    qca bulk execute <operation-id> --confirm-count <count> --wait
                    """)
            ],
            AutomationOperation.Inventory =>
            [
                new("list", "List certificates", "JSON output is the contract the API returns, in camelCase.",
                    "qca cert list --status issued --output json"),
                new("inventory", "Export the inventory",
                    "One item per certificate with parsed facts and the owner; never private-key material.",
                    "qca cert inventory --output json")
            ],
            AutomationOperation.Metadata =>
            [
                new("metadata-set", "Record the owner and ticket for the certificate",
                    "Replaces the whole set: every option you leave out is cleared, so show it first. The requester or certificates.manage can set it. Never put keys or secrets here.",
                    $"""
                    qca cert metadata show {target}
                    qca cert metadata set {target} --owner-team <team> --contact-email <email> --ticket <ticket>
                    """)
            ],
            AutomationOperation.Webhooks =>
            [
                new("webhooks-list", "List webhook subscriptions",
                    "Needs settings.edit. The table never prints secrets, but --output json includes each signing secret: keep that out of job logs.",
                    "qca webhooks list"),
                new("webhooks-create", "Create a webhook subscription",
                    "Omit --event to receive the whole family. With --secret each delivery carries an X-Webhook-Signature header (HMAC-SHA256 of the body); take the secret from the pipeline's secret store.",
                    "qca webhooks create --name <name> --url <https-url> --event Issued --secret <secret>")
            ],
            _ => throw new ArgumentOutOfRangeException(nameof(operation), operation, null)
        };
    }
}
