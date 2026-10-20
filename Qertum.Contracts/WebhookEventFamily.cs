using System.Text.Json.Serialization;

namespace Qertum.Services;

/// <summary>
/// The kind of resource a webhook event is about. A <see cref="Webhook"/> subscribes to exactly one
/// family; the family also decides which fields the delivery body and URL placeholders may carry.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum WebhookEventFamily
{
    /// <summary>Certificate request lifecycle: creation through issuance, revocation and deletion.</summary>
    CertificateRequest = 0,

    /// <summary>Changes to the singleton <see cref="CaSettings"/> row.</summary>
    Settings = 1,

    /// <summary>Certificate template CRUD and policy links.</summary>
    Template = 2,

    /// <summary>Issuance policy CRUD, draft edits and publication.</summary>
    Policy = 3,

    /// <summary>
    /// Key material leaving the system. These events deliberately disclose less than the others:
    /// no resource id and no common name, only the exported key's public-key thumbprint.
    /// </summary>
    KeyAccess = 4,

    /// <summary>Issuer (CA) registration, ceremonies, rollover and force replacement.</summary>
    Issuer = 5,

    /// <summary>Bulk revoke and bulk renew operations: one event when a run finishes.</summary>
    BulkOperation = 6,

    /// <summary>
    /// Expiry and renewal notices: a certificate nearing expiry, a renewal stalled in approval or one that failed.
    /// The only family whose payload carries the certificate's contact email, because delivering to that contact is its purpose.
    /// </summary>
    Notice = 7,

    /// <summary>
    /// Audit log checkpoints: the head of every audit hash chain, sent periodically so the receiver holds an
    /// off-host anchor to verify a copied log against. Carries hashes and sequence numbers, no audit content.
    /// </summary>
    Audit = 8,

    /// <summary>
    /// Two-person approval: a sensitive operation was requested, approved, denied, or an approval used.
    /// Carries ids, the operation key and the people's names; never the requester's or decider's note.
    /// </summary>
    Approval = 9
}
