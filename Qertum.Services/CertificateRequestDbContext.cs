using System.Security.Cryptography;
using Qertum.Services.Acme;
using Qertum.Services.Webhooks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Qertum.Services;

public sealed class CertificateRequestDbContext(
    DbContextOptions<CertificateRequestDbContext> options,
    IDataProtectionProvider dataProtectionProvider) : DbContext(options)
{
    /// <summary>
    /// Name of the filtered unique index enforcing one active request per common name. Referenced by
    /// <see cref="CertificateRequestService"/> to recognize the constraint violation it must surface
    /// as a duplicate-request error.
    /// </summary>
    internal const string ActiveCommonNameIndexName = "IX_CertificateRequests_CommonName_Active";

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        // The value converters built in OnModelCreating close over IDataProtector instances, and EF
        // caches the compiled model per context type — so without this the first provider a process
        // ever used stays baked into the model and is still called after it has been disposed. One
        // provider per process makes that invisible in production and intermittent in tests, where
        // each host builds its own. Keying the cache on the provider keeps model and protector
        // together.
        optionsBuilder.ReplaceService<IModelCacheKeyFactory, DataProtectionModelCacheKeyFactory>();
        base.OnConfiguring(optionsBuilder);
    }

    /// <summary>The provider whose protectors are baked into this context's model.</summary>
    internal IDataProtectionProvider DataProtectionProvider => dataProtectionProvider;

    public DbSet<CertificateRequest> CertificateRequests => Set<CertificateRequest>();

    public DbSet<CaSettings> Settings => Set<CaSettings>();

    /// <summary>Time-limited exceptions to PQC stage enforcement.</summary>
    public DbSet<PqcException> PqcExceptions => Set<PqcException>();

    public DbSet<RolePermission> RolePermissions => Set<RolePermission>();

    public DbSet<ObservedRole> ObservedRoles => Set<ObservedRole>();

    public DbSet<CertificateTemplate> CertificateTemplates => Set<CertificateTemplate>();

    public DbSet<AcmeAccount> AcmeAccounts => Set<AcmeAccount>();

    public DbSet<AcmeOrder> AcmeOrders => Set<AcmeOrder>();

    public DbSet<AcmeAuthorization> AcmeAuthorizations => Set<AcmeAuthorization>();

    public DbSet<AcmeChallenge> AcmeChallenges => Set<AcmeChallenge>();

    public DbSet<AcmeExternalAccountKey> AcmeExternalAccountKeys => Set<AcmeExternalAccountKey>();

    public DbSet<Est.EstEnrollmentCredential> EstEnrollmentCredentials => Set<Est.EstEnrollmentCredential>();

    public DbSet<Webhook> Webhooks => Set<Webhook>();

    public DbSet<WebhookDelivery> WebhookDeliveries => Set<WebhookDelivery>();

    public DbSet<BackgroundJob> BackgroundJobs => Set<BackgroundJob>();
    public DbSet<BulkOperation> BulkOperations => Set<BulkOperation>();
    public DbSet<BulkOperationItem> BulkOperationItems => Set<BulkOperationItem>();
    public DbSet<ApprovalRequest> ApprovalRequests => Set<ApprovalRequest>();

    /// <summary>Expiry and renewal notices: the once-only record and the in-app list.</summary>
    public DbSet<Notice> Notices => Set<Notice>();

    /// <summary>Administrative notes on certificate requests.</summary>
    public DbSet<CertificateNote> CertificateNotes => Set<CertificateNote>();

    /// <summary>Certificate authorities known to this server.</summary>
    public DbSet<Issuer> Issuers => Set<Issuer>();

    /// <summary>The singleton webhook destination policy state.</summary>
    public DbSet<WebhookDestinationPolicyState> WebhookDestinationPolicyStates => Set<WebhookDestinationPolicyState>();

    /// <summary>Configuration and administrator destination rules.</summary>
    public DbSet<WebhookDestinationRule> WebhookDestinationRules => Set<WebhookDestinationRule>();

    public DbSet<IssuancePolicy> IssuancePolicies => Set<IssuancePolicy>();

    public DbSet<IssuancePolicyVersion> IssuancePolicyVersions => Set<IssuancePolicyVersion>();

    public DbSet<Lifecycle.LifecycleEvent> LifecycleEvents => Set<Lifecycle.LifecycleEvent>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        var destinationState = modelBuilder.Entity<WebhookDestinationPolicyState>();
        destinationState.HasKey(state => state.Id);
        destinationState.ToTable(table => table.HasCheckConstraint("CK_WebhookDestinationPolicyState_Id", "Id = 1"));
        destinationState.Property(state => state.JsonPublicMode).HasConversion<string>().HasMaxLength(20);
        destinationState.Property(state => state.AdminPublicMode).HasConversion<string>().HasMaxLength(20);

        var destinationRule = modelBuilder.Entity<WebhookDestinationRule>();
        destinationRule.HasKey(rule => rule.Id);
        destinationRule.Property(rule => rule.Source).HasMaxLength(20).IsRequired();
        destinationRule.Property(rule => rule.StableKey).HasMaxLength(1000).IsRequired();
        destinationRule.Property(rule => rule.Kind).HasConversion<string>().HasMaxLength(20);
        destinationRule.Property(rule => rule.Scheme).HasMaxLength(5).IsRequired();
        destinationRule.Property(rule => rule.Host).HasMaxLength(255).IsRequired();
        destinationRule.Property(rule => rule.AllowedIpAddressesJson).HasMaxLength(4000).IsRequired();
        destinationRule.HasIndex(rule => new { rule.Source, rule.StableKey }).IsUnique();

        var certificateRequest = modelBuilder.Entity<CertificateRequest>();

        certificateRequest.HasKey(request => request.Id);
        certificateRequest.Property(r => r.Id)
            .HasConversion(id => id.Value, g => new CertificateRequestId(g));
        certificateRequest.Property(r => r.RenewedFromId)
            .HasConversion(
                id => id.HasValue ? id.Value.Value : (Guid?)null,
                g => g.HasValue ? new CertificateRequestId?(new CertificateRequestId(g.Value)) : null);
        certificateRequest.Property(request => request.CommonName).IsRequired();
        certificateRequest.Property(request => request.RequestedBy).IsRequired();
        certificateRequest.Property(request => request.Status).HasConversion<string>();
        certificateRequest.Property(r => r.KeyAlgorithm).HasConversion(
            v => v == null ? null : v.Value.ToCanonicalString(),
            v => CertificateKeyAlgorithmExtensions.Parse(v));

        // Six nullable columns on the request row (Metadata_OwnerTeam, ...); all null reads back as an empty set.
        certificateRequest.ComplexProperty(r => r.Metadata);

        // Composite index used by status-filter queries and the dequeue loop
        certificateRequest.HasIndex(r => new { r.Status, r.CreatedAtUtc });
        certificateRequest.Property(r => r.IssuerId)
            .HasConversion(
                id => id.HasValue ? id.Value.Value : (Guid?)null,
                g => g.HasValue ? new IssuerId?(new IssuerId(g.Value)) : null);
        // Per-issuer CRL and OCSP queries filter on it.
        certificateRequest.HasIndex(r => new { r.IssuerId, r.Status });
        // The renewal lookups (notices, auto-renewal, bulk renew) ask "does this certificate have a live renewal".
        certificateRequest.HasIndex(r => new { r.RenewedFromId, r.Status });
        // Covering index for the dequeue query: status + id (avoids table scan)
        certificateRequest.HasIndex(r => new { r.Status, r.Id });

        // One active request per common name. The check in CreateAsync reads before it writes, so on
        // its own two concurrent creates both pass it; this is what actually holds the line.
        // Filtered to match that check exactly, carve-outs included: terminal rows (Rejected/Revoked)
        // release the name; root CA requests are unique by type, not by CN; and renewals deliberately
        // reuse the CN of the certificate they replace, which is why RenewAsync inserts without going
        // through the check at all. Type is nullable, hence the explicit IS NULL arm — "Type <>
        // 'RootCA'" alone would drop those rows from the index and silently stop enforcing anything
        // for them. Widening this filter beyond what CreateAsync checks would reject workflows the
        // application considers legal.
        certificateRequest.HasIndex(r => r.CommonName)
            .IsUnique()
            .HasDatabaseName(ActiveCommonNameIndexName)
            .HasFilter(
                $"\"Status\" NOT IN ('{nameof(CertificateRequestStatus.Rejected)}', '{nameof(CertificateRequestStatus.Revoked)}') " +
                $"AND (\"Type\" IS NULL OR \"Type\" <> '{WellKnownCertificateTypes.RootCa}') " +
                "AND \"RenewedFromId\" IS NULL");

        // A CA must never sign two certificates under the same serial. Serials are 159-bit CSPRNG
        // values, so a collision is vanishingly unlikely — this index is what makes it *impossible*
        // to persist one instead of merely improbable. Filtered so the many not-yet-issued rows,
        // which all carry NULL, do not collide with each other.
        certificateRequest.Property(r => r.SerialNumber).HasMaxLength(64);
        certificateRequest.HasIndex(r => r.SerialNumber)
            .IsUnique()
            .HasFilter("\"SerialNumber\" IS NOT NULL");

        // The PQC certificate of a hybrid pair carries its own serial, under the same rule.
        certificateRequest.Property(r => r.PqcSerialNumber).HasMaxLength(64);
        certificateRequest.HasIndex(r => r.PqcSerialNumber)
            .IsUnique()
            .HasFilter("\"PqcSerialNumber\" IS NOT NULL");

        // Encrypt private keys at rest. Legacy rows that still contain a plain
        // PEM string are passed through transparently so existing data is not lost.
        var protector = dataProtectionProvider.CreateProtector("Qertum.Services.PrivateKey");
        var privateKeyConverter = new ValueConverter<string?, string?>(
            v => v == null ? null : protector.Protect(v),
            v => DecryptOrPassThrough(protector, v));
        certificateRequest.Property(r => r.PrivateKeyPem).HasConversion(privateKeyConverter);

        var caSettings = modelBuilder.Entity<CaSettings>();
        caSettings.ToTable(t => t.HasCheckConstraint("CK_CaSettings_Id", "\"Id\" = 1"));
        caSettings.HasKey(s => s.Id);
        caSettings.Property(s => s.PqcStage).HasConversion<string>().HasMaxLength(20)
            .HasDefaultValue(PqcStage.Enforce).HasSentinel((PqcStage)(-1)); // Off is a real value; only "unset" takes the column default
        caSettings.Property(s => s.IssuerStrengthMode).HasConversion<string>().HasMaxLength(20)
            .HasDefaultValue(IssuerStrengthMode.Warn).HasSentinel((IssuerStrengthMode)(-1)); // same sentinel: Off is a real value
        caSettings.Property(s => s.RevokedIssuerMode).HasConversion<string>().HasMaxLength(20)
            .HasDefaultValue(RevokedIssuerMode.HardStop).HasSentinel((RevokedIssuerMode)(-1)); // HardStop is the zero value and a real one

        var rolePermission = modelBuilder.Entity<RolePermission>();
        rolePermission.HasKey(rp => rp.Id);
        // NOCASE on the column, not in queries: SQLite indexes and IN/= comparisons take the
        // column's collation, so the unique index and every lookup agree that Ops == ops.
        rolePermission.Property(rp => rp.Role).IsRequired().HasMaxLength(RoleNameRules.MaxLength).UseCollation("NOCASE");
        rolePermission.Property(rp => rp.Permission).IsRequired();
        rolePermission.HasIndex(rp => new { rp.Role, rp.Permission }).IsUnique();

        var observedRole = modelBuilder.Entity<ObservedRole>();
        observedRole.HasKey(r => r.Role);
        observedRole.Property(r => r.Role).HasMaxLength(RoleNameRules.MaxLength).UseCollation("NOCASE");

        var acmeAccount = modelBuilder.Entity<AcmeAccount>();
        acmeAccount.HasKey(a => a.Id);
        acmeAccount.Property(a => a.JwkThumbprint).IsRequired().HasMaxLength(100);
        acmeAccount.Property(a => a.Status).IsRequired().HasMaxLength(20);
        acmeAccount.HasIndex(a => a.JwkThumbprint).IsUnique();
        acmeAccount.HasMany(a => a.Orders).WithOne(o => o.Account).HasForeignKey(o => o.AccountId);

        var acmeOrder = modelBuilder.Entity<AcmeOrder>();
        acmeOrder.HasKey(o => o.Id);
        acmeOrder.Property(o => o.Status).IsRequired().HasMaxLength(20);
        acmeOrder.HasIndex(o => new { o.AccountId, o.Status });
        acmeOrder.HasIndex(o => o.CertificateRequestId);
        acmeOrder.HasMany(o => o.Authorizations).WithOne(a => a.Order).HasForeignKey(a => a.OrderId);

        var acmeAuth = modelBuilder.Entity<AcmeAuthorization>();
        acmeAuth.HasKey(a => a.Id);
        acmeAuth.Property(a => a.Status).IsRequired().HasMaxLength(20);
        acmeAuth.Property(a => a.IdentifierType).IsRequired().HasMaxLength(10);
        acmeAuth.Property(a => a.IdentifierValue).IsRequired().HasMaxLength(253);
        acmeAuth.HasIndex(a => a.OrderId);
        acmeAuth.HasMany(a => a.Challenges).WithOne(c => c.Authorization).HasForeignKey(c => c.AuthorizationId);

        var acmeChallenge = modelBuilder.Entity<AcmeChallenge>();
        acmeChallenge.HasKey(c => c.Id);
        acmeChallenge.Property(c => c.Type).IsRequired().HasMaxLength(20);
        acmeChallenge.Property(c => c.Status).IsRequired().HasMaxLength(20);
        acmeChallenge.Property(c => c.Token).IsRequired().HasMaxLength(100);
        acmeChallenge.HasIndex(c => c.Token).IsUnique();
        acmeChallenge.HasIndex(c => new { c.AuthorizationId, c.Type });

        // The MAC key is a bearer credential for account creation, so it is encrypted at rest the same
        // way webhook secrets are.
        var eabProtector = dataProtectionProvider.CreateProtector("Qertum.Services.AcmeExternalAccountKey");
        var eabKeyConverter = new ValueConverter<string, string>(
            v => eabProtector.Protect(v),
            v => DecryptOrPassThrough(eabProtector, v) ?? string.Empty);

        var eabKey = modelBuilder.Entity<AcmeExternalAccountKey>();
        eabKey.HasKey(k => k.Id);
        eabKey.Property(k => k.Kid).IsRequired().HasMaxLength(64);
        eabKey.Property(k => k.MacKey).IsRequired().HasMaxLength(512).HasConversion(eabKeyConverter);
        eabKey.Property(k => k.Description).HasMaxLength(200);
        eabKey.HasIndex(k => k.Kid).IsUnique();

        var estCredential = modelBuilder.Entity<Est.EstEnrollmentCredential>();
        estCredential.HasIndex(c => c.Username).IsUnique();

        var webhookProtector = dataProtectionProvider.CreateProtector("Qertum.Services.WebhookSecret");
        var webhookSecretConverter = new ValueConverter<string?, string?>(
            v => v == null ? null : webhookProtector.Protect(v),
            v => DecryptOrPassThrough(webhookProtector, v));

        var webhook = modelBuilder.Entity<Webhook>();
        webhook.HasKey(w => w.Id);
        webhook.Property(w => w.Id)
            .HasConversion(id => id.Value, g => new WebhookId(g));
        webhook.Property(w => w.Name).IsRequired().HasMaxLength(200);
        webhook.Property(w => w.Url).IsRequired().HasMaxLength(2000);
        webhook.Property(w => w.Family).HasConversion<string>().IsRequired().HasMaxLength(30);
        webhook.Property(w => w.Secret).HasConversion(webhookSecretConverter);
        webhook.Property(w => w.EventsJson).IsRequired();
        webhook.HasIndex(w => w.IsEnabled);
        webhook.HasMany<WebhookDelivery>().WithOne().HasForeignKey(d => d.WebhookId);

        var webhookDelivery = modelBuilder.Entity<WebhookDelivery>();
        webhookDelivery.HasKey(d => d.Id);
        webhookDelivery.Property(d => d.WebhookId)
            .HasConversion(id => id.Value, g => new WebhookId(g));
        webhookDelivery.Property(d => d.EventType).IsRequired().HasMaxLength(50);
        webhookDelivery.Property(d => d.Status).IsRequired().HasMaxLength(20);
        webhookDelivery.Property(d => d.Payload).IsRequired();
        webhookDelivery.Property(d => d.ResolvedUrl).HasMaxLength(4000);
        // Primary query used by delivery service: pending rows due for retry
        webhookDelivery.HasIndex(d => new { d.Status, d.NextAttemptAfterUtc });
        webhookDelivery.HasIndex(d => d.WebhookId);

        var issuer = modelBuilder.Entity<Issuer>();
        issuer.HasKey(i => i.Id);
        issuer.Property(i => i.Id).HasConversion(id => id.Value, g => new IssuerId(g));
        issuer.Property(i => i.ParentIssuerId).HasConversion(
            id => id.HasValue ? id.Value.Value : (Guid?)null,
            g => g.HasValue ? new IssuerId?(new IssuerId(g.Value)) : null);
        issuer.Property(i => i.Name).IsRequired().HasMaxLength(200);
        issuer.Property(i => i.Kind).HasConversion<string>().HasMaxLength(20);
        issuer.Property(i => i.KeyCustody).HasConversion<string>().HasMaxLength(20);
        issuer.Property(i => i.Status).HasConversion<string>().HasMaxLength(20);
        issuer.Property(i => i.KeyAlgorithm).HasConversion(
            v => v == null ? null : v.Value.ToCanonicalString(),
            v => CertificateKeyAlgorithmExtensions.Parse(v));
        issuer.Property(i => i.SpkiSha256).IsRequired().HasMaxLength(64);
        issuer.Property(i => i.SubjectDn).HasMaxLength(2000);
        issuer.Property(i => i.SerialNumber).HasMaxLength(64);
        issuer.Property(i => i.SubjectKeyIdentifier).HasMaxLength(128);
        issuer.Property(i => i.CrlDistributionPoint).HasMaxLength(2000);
        issuer.Property(i => i.OcspResponderUrl).HasMaxLength(2000);
        issuer.Property(i => i.CaIssuersUrl).HasMaxLength(2000);
        issuer.HasIndex(i => i.Name).IsUnique();
        issuer.HasIndex(i => i.SpkiSha256).IsUnique();
        // At most one default. SQLite checks it per statement, so switching the default clears the
        // old flag in its own SaveChanges first (see IssuerLifecycleService.MakeDefaultAsync).
        issuer.HasIndex(i => i.IsDefault).IsUnique().HasFilter("\"IsDefault\" = 1");
        issuer.HasOne<Issuer>().WithMany().HasForeignKey(i => i.ParentIssuerId).OnDelete(DeleteBehavior.Restrict);

        var backgroundJob = modelBuilder.Entity<BackgroundJob>();
        backgroundJob.HasKey(j => j.Id);
        backgroundJob.Property(j => j.Id)
            .HasConversion(id => id.Value, g => new BackgroundJobId(g));
        backgroundJob.Property(j => j.JobType).IsRequired().HasMaxLength(100);
        backgroundJob.Property(j => j.Status).HasConversion<string>().HasMaxLength(20);
        backgroundJob.Property(j => j.ConcurrencyKey).HasMaxLength(200);
        backgroundJob.Property(j => j.RequestedBy).IsRequired().HasMaxLength(200);
        backgroundJob.Property(j => j.Reason).HasMaxLength(500);
        backgroundJob.Property(j => j.Result).HasMaxLength(500);
        backgroundJob.Property(j => j.FailureReason).HasMaxLength(2000);
        // One active job per key; finished jobs release it. SQLite checks this per statement, so two
        // producers racing to enqueue cannot both win.
        backgroundJob.HasIndex(j => j.ConcurrencyKey)
            .IsUnique()
            .HasFilter($"\"ConcurrencyKey\" IS NOT NULL AND \"Status\" IN ('{nameof(BackgroundJobStatus.Pending)}', '{nameof(BackgroundJobStatus.Processing)}')");
        // Claim query: due pending jobs.
        backgroundJob.HasIndex(j => new { j.Status, j.NextAttemptAfterUtc });

        var bulkOperation = modelBuilder.Entity<BulkOperation>();
        bulkOperation.HasKey(o => o.Id);
        bulkOperation.Property(o => o.Id).HasConversion(id => id.Value, g => new BulkOperationId(g));
        bulkOperation.Property(o => o.Kind).HasConversion<string>().HasMaxLength(20);
        bulkOperation.Property(o => o.Status).HasConversion<string>().HasMaxLength(30);
        bulkOperation.Property(o => o.FilterJson).IsRequired();
        bulkOperation.Property(o => o.Reason).HasMaxLength(500);
        bulkOperation.Property(o => o.CreatedBy).IsRequired().HasMaxLength(200);
        bulkOperation.Property(o => o.CreatedBySubject).HasMaxLength(200);
        bulkOperation.Property(o => o.ExecutedBy).HasMaxLength(200);
        bulkOperation.HasIndex(o => new { o.Status, o.CreatedAtUtc });

        var approval = modelBuilder.Entity<ApprovalRequest>();
        approval.HasKey(a => a.Id);
        approval.Property(a => a.Id).HasConversion(id => id.Value, g => new ApprovalRequestId(g));
        approval.Property(a => a.Operation).IsRequired().HasMaxLength(64);
        approval.Property(a => a.TargetId).HasMaxLength(64);
        approval.Property(a => a.Note).HasMaxLength(500);
        approval.Property(a => a.RequestedBySubject).IsRequired().HasMaxLength(200);
        approval.Property(a => a.RequestedByName).IsRequired().HasMaxLength(200);
        approval.Property(a => a.Status).HasConversion<string>().HasMaxLength(20);
        approval.Property(a => a.DecidedBySubject).HasMaxLength(200);
        approval.Property(a => a.DecidedByName).HasMaxLength(200);
        approval.Property(a => a.DecisionNote).HasMaxLength(500);
        // Claim query: this caller's approved grant for one operation and target.
        approval.HasIndex(a => new { a.RequestedBySubject, a.Operation, a.TargetId, a.Status });
        // One open request per caller, operation and target, enforced by the database so two simultaneous requests cannot both be filed.
        // A request without a target (creating an intermediate) is not covered: SQLite treats NULLs as distinct, and a duplicate there is harmless.
        approval.HasIndex(a => new { a.RequestedBySubject, a.Operation, a.TargetId })
            .IsUnique()
            .HasDatabaseName("UX_ApprovalRequests_OpenPerKey")
            .HasFilter($"\"TargetId\" IS NOT NULL AND \"Status\" IN ('{nameof(ApprovalStatus.Pending)}', '{nameof(ApprovalStatus.Approved)}')");

        var bulkItem = modelBuilder.Entity<BulkOperationItem>();
        bulkItem.HasKey(i => new { i.OperationId, i.RequestId });
        bulkItem.Property(i => i.OperationId).HasConversion(id => id.Value, g => new BulkOperationId(g));
        bulkItem.Property(i => i.RequestId).HasConversion(id => id.Value, g => new CertificateRequestId(g));
        bulkItem.Property(i => i.ResultRequestId).HasConversion(
            id => id.HasValue ? id.Value.Value : (Guid?)null,
            g => g.HasValue ? new CertificateRequestId?(new CertificateRequestId(g.Value)) : null);
        bulkItem.Property(i => i.Outcome).HasConversion<string>().HasMaxLength(20);
        bulkItem.Property(i => i.Detail).HasMaxLength(1000);
        bulkItem.HasOne<BulkOperation>().WithMany().HasForeignKey(i => i.OperationId).OnDelete(DeleteBehavior.Cascade);
        // Resume query: the pending items of one operation.
        bulkItem.HasIndex(i => new { i.OperationId, i.Outcome });

        var notice = modelBuilder.Entity<Notice>();
        notice.HasKey(n => n.Id);
        notice.Property(n => n.Id).HasConversion(id => id.Value, g => new NoticeId(g));
        notice.Property(n => n.RequestId).HasConversion(id => id.Value, g => new CertificateRequestId(g));
        notice.Property(n => n.SourceRequestId).HasConversion(
            id => id.HasValue ? id.Value.Value : (Guid?)null,
            g => g.HasValue ? new CertificateRequestId?(new CertificateRequestId(g.Value)) : null);
        notice.Property(n => n.Kind).HasConversion<string>().HasMaxLength(20);
        notice.Property(n => n.Status).HasConversion<string>().HasMaxLength(10);
        // The once-only record: one row per request, kind and step. No foreign key on purpose: a deleted
        // request leaves its notice for the sweeper to resolve, and the list shows it without a name.
        notice.HasIndex(n => new { n.RequestId, n.Kind, n.Step }).IsUnique();
        notice.HasIndex(n => new { n.Status, n.CreatedAtUtc });

        var certificateNote = modelBuilder.Entity<CertificateNote>();
        certificateNote.HasKey(n => n.Id);
        certificateNote.Property(n => n.Id).HasConversion(id => id.Value, g => new NoteId(g));
        certificateNote.Property(n => n.RequestId).HasConversion(id => id.Value, g => new CertificateRequestId(g));
        certificateNote.Property(n => n.Body).IsRequired().HasMaxLength(CertificateNote.MaxBodyLength);
        certificateNote.Property(n => n.AuthorSubject).IsRequired().HasMaxLength(200);
        certificateNote.Property(n => n.AuthorName).IsRequired().HasMaxLength(200);
        // The timeline reads one request's notes in order. No foreign key: the request's deletion removes its notes
        // explicitly (SQLite cascades only with foreign keys on).
        certificateNote.HasIndex(n => new { n.RequestId, n.CreatedAtUtc });


        var issuancePolicy = modelBuilder.Entity<IssuancePolicy>();
        issuancePolicy.HasKey(p => p.Id);
        issuancePolicy.Property(p => p.Id)
            .HasConversion(id => id.Value, g => new IssuancePolicyId(g));
        issuancePolicy.Property(p => p.Name).IsRequired().HasMaxLength(100);
        issuancePolicy.Property(p => p.Description).HasMaxLength(500);
        issuancePolicy.HasIndex(p => p.Name).IsUnique();
        issuancePolicy.HasMany(p => p.Versions)
            .WithOne()
            .HasForeignKey(v => v.PolicyId)
            .OnDelete(DeleteBehavior.Cascade);

        var policyVersion = modelBuilder.Entity<IssuancePolicyVersion>();
        policyVersion.HasKey(v => v.Id);
        policyVersion.Property(v => v.PolicyId)
            .HasConversion(id => id.Value, g => new IssuancePolicyId(g));
        policyVersion.Property(v => v.Status).HasConversion<string>().HasMaxLength(20);
        policyVersion.Property(v => v.KeyCustody).HasConversion<string>().HasMaxLength(30);
        policyVersion.Property(v => v.CreatedBy).IsRequired().HasMaxLength(200);
        policyVersion.Property(v => v.PublishedBy).HasMaxLength(200);
        policyVersion.HasIndex(v => new { v.PolicyId, v.VersionNumber }).IsUnique();
        // At most one draft and one published version per policy. Publish supersedes the old
        // published row in a separate SaveChanges before promoting the draft, because SQLite checks
        // these per statement and EF does not guarantee UPDATE ordering within one batch.
        policyVersion.HasIndex(v => v.PolicyId, "IX_IssuancePolicyVersions_OneDraft")
            .IsUnique()
            .HasFilter($"\"Status\" = '{nameof(IssuancePolicyVersionStatus.Draft)}'");
        policyVersion.HasIndex(v => v.PolicyId, "IX_IssuancePolicyVersions_OnePublished")
            .IsUnique()
            .HasFilter($"\"Status\" = '{nameof(IssuancePolicyVersionStatus.Published)}'");

        // A request records the version that allowed it; the version cannot be deleted under it.
        certificateRequest.HasOne<IssuancePolicyVersion>()
            .WithMany()
            .HasForeignKey(r => r.PolicyVersionId)
            .OnDelete(DeleteBehavior.Restrict);

        var certTemplate = modelBuilder.Entity<CertificateTemplate>();
        certTemplate.HasKey(t => t.Id);
        certTemplate.Property(t => t.PqcStageOverride).HasConversion<string>().HasMaxLength(20);

        var pqcException = modelBuilder.Entity<PqcException>();
        pqcException.HasKey(e => e.Id);
        pqcException.Property(e => e.Id).HasConversion(id => id.Value, g => new PqcExceptionId(g));
        pqcException.Property(e => e.Family).HasConversion<string>().HasMaxLength(10);
        pqcException.Property(e => e.TemplateTypeKey).IsRequired().HasMaxLength(50);
        pqcException.Property(e => e.NamePattern).IsRequired().HasMaxLength(253);
        pqcException.Property(e => e.Reason).IsRequired().HasMaxLength(500);
        pqcException.Property(e => e.GrantedBy).IsRequired().HasMaxLength(200);
        pqcException.HasIndex(e => new { e.TemplateTypeKey, e.ExpiresAtUtc });
        certTemplate.Property(t => t.Id)
            .HasConversion(id => id.Value, g => new CertificateTemplateId(g));
        certTemplate.Property(t => t.Name).IsRequired().HasMaxLength(100);
        certTemplate.Property(t => t.TypeKey).IsRequired().HasMaxLength(50);
        certTemplate.HasIndex(t => t.TypeKey).IsUnique();
        certTemplate.Property(t => t.IssuerId)
            .HasConversion(
                id => id.HasValue ? id.Value.Value : (Guid?)null,
                g => g.HasValue ? new IssuerId?(new IssuerId(g.Value)) : null);
        certTemplate.Property(t => t.IssuancePolicyId)
            .HasConversion(
                id => id.HasValue ? id.Value.Value : (Guid?)null,
                g => g.HasValue ? new IssuancePolicyId?(new IssuancePolicyId(g.Value)) : null);
        certTemplate.HasOne<IssuancePolicy>()
            .WithMany()
            .HasForeignKey(t => t.IssuancePolicyId)
            .OnDelete(DeleteBehavior.Restrict);
        certTemplate.HasData(
            new CertificateTemplate
            {
                Id = new Guid("00000000-0000-0000-0000-000000000001"),
                Name = "Web Server (TLS)",
                TypeKey = "WebServer",
                Description = "Standard TLS server certificate with ServerAuth EKU and DNS/IP SAN support.",
                IsBuiltIn = true,
                KeyUsagesJson = """["DigitalSignature","KeyEncipherment"]""",
                ExtendedKeyUsagesJson = """["1.3.6.1.5.5.7.3.1"]""",
                SanTypesJson = """["dns","ip"]""",
                CreatedAtUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                UpdatedAtUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            },
            new CertificateTemplate
            {
                Id = new Guid("00000000-0000-0000-0000-000000000002"),
                Name = "Code Signing",
                TypeKey = "CodeSigning",
                Description = "Certificate for signing software, scripts, and executables.",
                IsBuiltIn = true,
                KeyUsagesJson = """["DigitalSignature"]""",
                ExtendedKeyUsagesJson = """["1.3.6.1.5.5.7.3.3"]""",
                SanTypesJson = "[]",
                CreatedAtUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                UpdatedAtUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            },
            new CertificateTemplate
            {
                Id = new Guid("00000000-0000-0000-0000-000000000003"),
                Name = "S/MIME Email",
                TypeKey = "SMIME",
                Description = "Certificate for signing and encrypting email (S/MIME). Requires an email address SAN.",
                IsBuiltIn = true,
                KeyUsagesJson = """["DigitalSignature","NonRepudiation","KeyEncipherment"]""",
                ExtendedKeyUsagesJson = """["1.3.6.1.5.5.7.3.4"]""",
                SanTypesJson = """["email"]""",
                CreatedAtUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                UpdatedAtUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            },
            new CertificateTemplate
            {
                Id = new Guid("00000000-0000-0000-0000-000000000004"),
                Name = "Client Authentication",
                TypeKey = "ClientAuth",
                Description = "Certificate for authenticating clients to servers (mutual TLS).",
                IsBuiltIn = true,
                KeyUsagesJson = """["DigitalSignature"]""",
                ExtendedKeyUsagesJson = """["1.3.6.1.5.5.7.3.2"]""",
                SanTypesJson = """["email","upn"]""",
                CreatedAtUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                UpdatedAtUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            },
            new CertificateTemplate
            {
                Id = new Guid("00000000-0000-0000-0000-000000000005"),
                Name = "Subordinate CA",
                TypeKey = "SubordinateCA",
                Description = "Intermediate CA certificate signed by this root CA. Can issue and sign leaf certificates on behalf of the root. Sets BasicConstraints CA:TRUE and KeyCertSign.",
                IsBuiltIn = true,
                KeyUsagesJson = """["KeyCertSign","CrlSign","DigitalSignature"]""",
                ExtendedKeyUsagesJson = "[]",
                SanTypesJson = "[]",
                ValidityDays = 3650,
                CreatedAtUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                UpdatedAtUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            });

        var lifecycleEvent = modelBuilder.Entity<Lifecycle.LifecycleEvent>();
        lifecycleEvent.HasKey(e => e.Id);
        lifecycleEvent.Property(e => e.Kind).IsRequired().HasMaxLength(20);
        lifecycleEvent.Property(e => e.SubjectType).IsRequired().HasMaxLength(50);
        lifecycleEvent.Property(e => e.Action).IsRequired().HasMaxLength(100);
        lifecycleEvent.Property(e => e.Category).HasMaxLength(50);
        lifecycleEvent.Property(e => e.PerformedBy).IsRequired().HasMaxLength(200);
        lifecycleEvent.Property(e => e.TraceId).HasMaxLength(64);
        // A timeline is one subject's events in time order; the sweep deletes by kind and age.
        lifecycleEvent.HasIndex(e => new { e.SubjectType, e.SubjectId, e.OccurredAtUtc });
        lifecycleEvent.HasIndex(e => new { e.Kind, e.OccurredAtUtc });
    }

    private static string? DecryptOrPassThrough(IDataProtector protector, string? value)
    {
        if (value == null) return null;
        try
        {
            return protector.Unprotect(value);
        }
        catch (CryptographicException)
        {
            // Legacy row: stored as plain PEM before encryption was introduced.
            return value.StartsWith("-----BEGIN", StringComparison.Ordinal) ? value : null;
        }
    }
}

/// <summary>
/// Includes the Data Protection provider in EF's model cache key, so two contexts with different
/// providers do not share a model carrying the other's protectors.
/// </summary>
internal sealed class DataProtectionModelCacheKeyFactory : IModelCacheKeyFactory
{
    public object Create(DbContext context, bool designTime) =>
        context is CertificateRequestDbContext qertum
            ? (context.GetType(), qertum.DataProtectionProvider, designTime)
            : (context.GetType(), designTime);
}
