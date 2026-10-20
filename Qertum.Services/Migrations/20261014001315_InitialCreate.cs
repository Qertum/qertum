using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace Qertum.Services.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AcmeAccounts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    JwkThumbprint = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    PublicKeyJwk = table.Column<string>(type: "TEXT", maxLength: 4096, nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    TermsOfServiceAgreed = table.Column<bool>(type: "INTEGER", nullable: false),
                    ContactsJson = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    ExternalAccountKid = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AcmeAccounts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AcmeExternalAccountKeys",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Kid = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    MacKey = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    IsEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    BoundAccountId = table.Column<Guid>(type: "TEXT", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    BoundAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AcmeExternalAccountKeys", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ApprovalRequests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Operation = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    TargetId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    Note = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    RequestedBySubject = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    RequestedByName = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    RequestedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    DecidedBySubject = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    DecidedByName = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    DecidedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    DecisionNote = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    GrantExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    UsedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ApprovalRequests", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "BackgroundJobs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    JobType = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    ConcurrencyKey = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    PayloadJson = table.Column<string>(type: "TEXT", nullable: true),
                    RequestedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Reason = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    RequestedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ClaimedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    CompletedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    NextAttemptAfterUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    AttemptCount = table.Column<int>(type: "INTEGER", nullable: false),
                    Result = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    FailureReason = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BackgroundJobs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "BulkOperations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Kind = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 30, nullable: false),
                    FilterJson = table.Column<string>(type: "TEXT", nullable: false),
                    Reason = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    CreatedBySubject = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ExecutedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    ExecutedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    StartedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    FinishedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    CallerSnapshotJson = table.Column<string>(type: "TEXT", nullable: true),
                    ItemCount = table.Column<int>(type: "INTEGER", nullable: false),
                    DoneCount = table.Column<int>(type: "INTEGER", nullable: false),
                    SkippedCount = table.Column<int>(type: "INTEGER", nullable: false),
                    FailedCount = table.Column<int>(type: "INTEGER", nullable: false),
                    ExcludedJson = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BulkOperations", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CertificateNotes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    RequestId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Body = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    AuthorSubject = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    AuthorName = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateNotes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "EstEnrollmentCredentials",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Username = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    PasswordHash = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    IsEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EstEnrollmentCredentials", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "IssuancePolicies",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    IsArchived = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IssuancePolicies", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Issuers",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Kind = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    ParentIssuerId = table.Column<Guid>(type: "TEXT", nullable: true),
                    KeyCustody = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    IsDefault = table.Column<bool>(type: "INTEGER", nullable: false),
                    LegacyFiles = table.Column<bool>(type: "INTEGER", nullable: false),
                    CertificatePem = table.Column<string>(type: "TEXT", nullable: true),
                    CsrPem = table.Column<string>(type: "TEXT", nullable: true),
                    KeyAlgorithm = table.Column<string>(type: "TEXT", nullable: true),
                    SpkiSha256 = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    SubjectDn = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    SerialNumber = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    SubjectKeyIdentifier = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    ValidFrom = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ValidTo = table.Column<DateTime>(type: "TEXT", nullable: true),
                    PathLengthConstraint = table.Column<int>(type: "INTEGER", nullable: true),
                    PermittedDnsSuffixesJson = table.Column<string>(type: "TEXT", nullable: false),
                    ExcludedDnsSuffixesJson = table.Column<string>(type: "TEXT", nullable: false),
                    PermittedIpRangesJson = table.Column<string>(type: "TEXT", nullable: false),
                    ExcludedIpRangesJson = table.Column<string>(type: "TEXT", nullable: false),
                    RequestedConstraintsJson = table.Column<string>(type: "TEXT", nullable: true),
                    CrlNumber = table.Column<long>(type: "INTEGER", nullable: false),
                    BaseCrlNumber = table.Column<long>(type: "INTEGER", nullable: true),
                    BaseCrlThisUpdateUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    UploadedCrlDer = table.Column<byte[]>(type: "BLOB", nullable: true),
                    UploadedCrlNumber = table.Column<long>(type: "INTEGER", nullable: true),
                    UploadedCrlNextUpdateUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    CrlDistributionPoint = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    OcspResponderUrl = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    CaIssuersUrl = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ActivatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    RetiredAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ArchivedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    DestroyedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Issuers", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Issuers_Issuers_ParentIssuerId",
                        column: x => x.ParentIssuerId,
                        principalTable: "Issuers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "LifecycleEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Kind = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    OccurredAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    SubjectType = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    SubjectId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Action = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Category = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    PerformedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Detail = table.Column<string>(type: "TEXT", nullable: true),
                    DataJson = table.Column<string>(type: "TEXT", nullable: true),
                    TraceId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LifecycleEvents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Notices",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    RequestId = table.Column<Guid>(type: "TEXT", nullable: false),
                    SourceRequestId = table.Column<Guid>(type: "TEXT", nullable: true),
                    Kind = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    Step = table.Column<int>(type: "INTEGER", nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 10, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ResolvedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    WebhookQueuedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Notices", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ObservedRoles",
                columns: table => new
                {
                    Role = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false, collation: "NOCASE"),
                    FirstSeenUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastSeenUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ObservedRoles", x => x.Role);
                });

            migrationBuilder.CreateTable(
                name: "PqcExceptions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    TemplateTypeKey = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    NamePattern = table.Column<string>(type: "TEXT", maxLength: 253, nullable: false),
                    Family = table.Column<string>(type: "TEXT", maxLength: 10, nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Reason = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    GrantedBySubject = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    GrantedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    RevokedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    RevokedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PqcExceptions", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "RolePermissions",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Role = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false, collation: "NOCASE"),
                    Permission = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RolePermissions", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Settings",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    OrganizationName = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    OrganizationalUnit = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    Country = table.Column<string>(type: "TEXT", maxLength: 2, nullable: true),
                    State = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    Locality = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    CrlDistributionPoint = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    OcspResponderUrl = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    PublicBaseUrl = table.Column<string>(type: "TEXT", nullable: true),
                    AcmeRequireExternalAccountBinding = table.Column<bool>(type: "INTEGER", nullable: false),
                    ExpiringSoonDays = table.Column<int>(type: "INTEGER", nullable: false),
                    CertificateValidityDays = table.Column<int>(type: "INTEGER", nullable: false),
                    CrlValidityHours = table.Column<int>(type: "INTEGER", nullable: false),
                    AutoRevokeOnRenewal = table.Column<bool>(type: "INTEGER", nullable: false),
                    AcmeAutoApprove = table.Column<bool>(type: "INTEGER", nullable: false),
                    EstAutoApprove = table.Column<bool>(type: "INTEGER", nullable: false),
                    AutoRenewalEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    AutoRenewalDaysBeforeExpiry = table.Column<int>(type: "INTEGER", nullable: true),
                    AutoRenewalAutoApprove = table.Column<bool>(type: "INTEGER", nullable: false),
                    RequireTwoPersonApproval = table.Column<bool>(type: "INTEGER", nullable: false),
                    RequireIndependentCaApproval = table.Column<bool>(type: "INTEGER", nullable: false),
                    AcmeChallengeAllowedNetworksJson = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    CrlNumber = table.Column<long>(type: "INTEGER", nullable: false),
                    DeltaCrlEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    CrlDeltaDistributionPoint = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    DeltaCrlValidityHours = table.Column<int>(type: "INTEGER", nullable: false),
                    BaseCrlNumber = table.Column<long>(type: "INTEGER", nullable: true),
                    BaseCrlThisUpdateUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    AttentionPendingApprovalAgeHours = table.Column<int>(type: "INTEGER", nullable: false),
                    AttentionFailureLookbackDays = table.Column<int>(type: "INTEGER", nullable: false),
                    AttentionBackupMaxAgeHours = table.Column<int>(type: "INTEGER", nullable: false),
                    AttentionRestoreVerifiedMaxAgeDays = table.Column<int>(type: "INTEGER", nullable: false),
                    AcmeTemplateTypeKey = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    EstTemplateTypeKey = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    PqcStage = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false, defaultValue: "Enforce")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Settings", x => x.Id);
                    table.CheckConstraint("CK_CaSettings_Id", "\"Id\" = 1");
                });

            migrationBuilder.CreateTable(
                name: "WebhookDestinationPolicyStates",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Initialized = table.Column<bool>(type: "INTEGER", nullable: false),
                    JsonPublicMode = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    AdminPublicMode = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    ReconciledAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WebhookDestinationPolicyStates", x => x.Id);
                    table.CheckConstraint("CK_WebhookDestinationPolicyState_Id", "Id = 1");
                });

            migrationBuilder.CreateTable(
                name: "WebhookDestinationRules",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Source = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    StableKey = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false),
                    Kind = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    Scheme = table.Column<string>(type: "TEXT", maxLength: 5, nullable: false),
                    Host = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    Port = table.Column<int>(type: "INTEGER", nullable: false),
                    AllowedIpAddressesJson = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: false),
                    IsPresent = table.Column<bool>(type: "INTEGER", nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    AdminDisabled = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WebhookDestinationRules", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Webhooks",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Url = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    Family = table.Column<string>(type: "TEXT", maxLength: 30, nullable: false),
                    Secret = table.Column<string>(type: "TEXT", nullable: true),
                    EventsJson = table.Column<string>(type: "TEXT", nullable: false),
                    IsEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Webhooks", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AcmeOrders",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    AccountId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    IdentifiersJson = table.Column<string>(type: "TEXT", maxLength: 4096, nullable: false),
                    NotBefore = table.Column<DateTime>(type: "TEXT", nullable: true),
                    NotAfter = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CertificateRequestId = table.Column<Guid>(type: "TEXT", nullable: true),
                    CertificatePem = table.Column<string>(type: "TEXT", maxLength: 16384, nullable: true),
                    CsrPem = table.Column<string>(type: "TEXT", maxLength: 8192, nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AcmeOrders", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AcmeOrders_AcmeAccounts_AccountId",
                        column: x => x.AccountId,
                        principalTable: "AcmeAccounts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "BulkOperationItems",
                columns: table => new
                {
                    OperationId = table.Column<Guid>(type: "TEXT", nullable: false),
                    RequestId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Outcome = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    Detail = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    ResultRequestId = table.Column<Guid>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BulkOperationItems", x => new { x.OperationId, x.RequestId });
                    table.ForeignKey(
                        name: "FK_BulkOperationItems_BulkOperations_OperationId",
                        column: x => x.OperationId,
                        principalTable: "BulkOperations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "CertificateTemplates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    TypeKey = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    Description = table.Column<string>(type: "TEXT", nullable: true),
                    IsBuiltIn = table.Column<bool>(type: "INTEGER", nullable: false),
                    KeyUsagesJson = table.Column<string>(type: "TEXT", nullable: false),
                    ExtendedKeyUsagesJson = table.Column<string>(type: "TEXT", nullable: false),
                    SanTypesJson = table.Column<string>(type: "TEXT", nullable: false),
                    CustomExtensionsJson = table.Column<string>(type: "TEXT", nullable: true),
                    ValidityDays = table.Column<int>(type: "INTEGER", nullable: true),
                    IssuancePolicyId = table.Column<Guid>(type: "TEXT", nullable: true),
                    IssuerId = table.Column<Guid>(type: "TEXT", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    PqcStageOverride = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateTemplates", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CertificateTemplates_IssuancePolicies_IssuancePolicyId",
                        column: x => x.IssuancePolicyId,
                        principalTable: "IssuancePolicies",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "IssuancePolicyVersions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    PolicyId = table.Column<Guid>(type: "TEXT", nullable: false),
                    VersionNumber = table.Column<int>(type: "INTEGER", nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    AllowedDnsSuffixesJson = table.Column<string>(type: "TEXT", nullable: false),
                    AllowedIpRangesJson = table.Column<string>(type: "TEXT", nullable: false),
                    AllowedKeyAlgorithmsJson = table.Column<string>(type: "TEXT", nullable: false),
                    AllowedRequesterRolesJson = table.Column<string>(type: "TEXT", nullable: false),
                    KeyCustody = table.Column<string>(type: "TEXT", maxLength: 30, nullable: false),
                    MaxValidityDays = table.Column<int>(type: "INTEGER", nullable: true),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    PublishedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    PublishedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IssuancePolicyVersions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_IssuancePolicyVersions_IssuancePolicies_PolicyId",
                        column: x => x.PolicyId,
                        principalTable: "IssuancePolicies",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "WebhookDeliveries",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    WebhookId = table.Column<Guid>(type: "TEXT", nullable: false),
                    EventType = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    ResourceId = table.Column<Guid>(type: "TEXT", nullable: true),
                    ResourceName = table.Column<string>(type: "TEXT", nullable: true),
                    Payload = table.Column<string>(type: "TEXT", nullable: false),
                    ResolvedUrl = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    Status = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    AttemptCount = table.Column<int>(type: "INTEGER", nullable: false),
                    NextAttemptAfterUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastErrorMessage = table.Column<string>(type: "TEXT", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WebhookDeliveries", x => x.Id);
                    table.ForeignKey(
                        name: "FK_WebhookDeliveries_Webhooks_WebhookId",
                        column: x => x.WebhookId,
                        principalTable: "Webhooks",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AcmeAuthorizations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    OrderId = table.Column<Guid>(type: "TEXT", nullable: false),
                    IdentifierType = table.Column<string>(type: "TEXT", maxLength: 10, nullable: false),
                    IdentifierValue = table.Column<string>(type: "TEXT", maxLength: 253, nullable: false),
                    Wildcard = table.Column<bool>(type: "INTEGER", nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AcmeAuthorizations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AcmeAuthorizations_AcmeOrders_OrderId",
                        column: x => x.OrderId,
                        principalTable: "AcmeOrders",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "CertificateRequests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CommonName = table.Column<string>(type: "TEXT", nullable: false),
                    RequestedBy = table.Column<string>(type: "TEXT", nullable: false),
                    RequestedBySubject = table.Column<string>(type: "TEXT", nullable: true),
                    Status = table.Column<string>(type: "TEXT", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ValidFrom = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ValidTo = table.Column<DateTime>(type: "TEXT", nullable: true),
                    RevokedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    Type = table.Column<string>(type: "TEXT", nullable: true),
                    PropertiesJson = table.Column<string>(type: "TEXT", nullable: true),
                    CertificatePem = table.Column<string>(type: "TEXT", nullable: true),
                    PrivateKeyPem = table.Column<string>(type: "TEXT", nullable: true),
                    SerialNumber = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    PqcSerialNumber = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    RevocationReason = table.Column<string>(type: "TEXT", nullable: true),
                    RenewedFromId = table.Column<Guid>(type: "TEXT", nullable: true),
                    KeyAlgorithm = table.Column<string>(type: "TEXT", nullable: true),
                    PqcCertificatePem = table.Column<string>(type: "TEXT", nullable: true),
                    PqcPrivateKeyPem = table.Column<string>(type: "TEXT", nullable: true),
                    FailureReason = table.Column<string>(type: "TEXT", nullable: true),
                    CsrPem = table.Column<string>(type: "TEXT", nullable: true),
                    ValidityDays = table.Column<int>(type: "INTEGER", nullable: true),
                    PolicyVersionId = table.Column<Guid>(type: "TEXT", nullable: true),
                    PolicyEvaluatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    IssuerId = table.Column<Guid>(type: "TEXT", nullable: true),
                    Metadata_CompatibilityNote = table.Column<string>(type: "TEXT", nullable: true),
                    Metadata_ContactEmail = table.Column<string>(type: "TEXT", nullable: true),
                    Metadata_OwnerTeam = table.Column<string>(type: "TEXT", nullable: true),
                    Metadata_Purpose = table.Column<string>(type: "TEXT", nullable: true),
                    Metadata_TargetSystem = table.Column<string>(type: "TEXT", nullable: true),
                    Metadata_TicketReference = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateRequests", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CertificateRequests_IssuancePolicyVersions_PolicyVersionId",
                        column: x => x.PolicyVersionId,
                        principalTable: "IssuancePolicyVersions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "AcmeChallenges",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    AuthorizationId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Type = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    Token = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    ValidatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ErrorJson = table.Column<string>(type: "TEXT", maxLength: 4096, nullable: true),
                    ValidationAttempts = table.Column<int>(type: "INTEGER", nullable: false),
                    NextAttemptAfterUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AcmeChallenges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AcmeChallenges_AcmeAuthorizations_AuthorizationId",
                        column: x => x.AuthorizationId,
                        principalTable: "AcmeAuthorizations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.InsertData(
                table: "CertificateTemplates",
                columns: new[] { "Id", "CreatedAtUtc", "CustomExtensionsJson", "Description", "ExtendedKeyUsagesJson", "IsBuiltIn", "IssuancePolicyId", "IssuerId", "KeyUsagesJson", "Name", "PqcStageOverride", "SanTypesJson", "TypeKey", "UpdatedAtUtc", "ValidityDays" },
                values: new object[,]
                {
                    { new Guid("00000000-0000-0000-0000-000000000001"), new DateTime(2026, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, "Standard TLS server certificate with ServerAuth EKU and DNS/IP SAN support.", "[\"1.3.6.1.5.5.7.3.1\"]", true, null, null, "[\"DigitalSignature\",\"KeyEncipherment\"]", "Web Server (TLS)", null, "[\"dns\",\"ip\"]", "WebServer", new DateTime(2026, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), null },
                    { new Guid("00000000-0000-0000-0000-000000000002"), new DateTime(2026, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, "Certificate for signing software, scripts, and executables.", "[\"1.3.6.1.5.5.7.3.3\"]", true, null, null, "[\"DigitalSignature\"]", "Code Signing", null, "[]", "CodeSigning", new DateTime(2026, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), null },
                    { new Guid("00000000-0000-0000-0000-000000000003"), new DateTime(2026, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, "Certificate for signing and encrypting email (S/MIME). Requires an email address SAN.", "[\"1.3.6.1.5.5.7.3.4\"]", true, null, null, "[\"DigitalSignature\",\"NonRepudiation\",\"KeyEncipherment\"]", "S/MIME Email", null, "[\"email\"]", "SMIME", new DateTime(2026, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), null },
                    { new Guid("00000000-0000-0000-0000-000000000004"), new DateTime(2026, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, "Certificate for authenticating clients to servers (mutual TLS).", "[\"1.3.6.1.5.5.7.3.2\"]", true, null, null, "[\"DigitalSignature\"]", "Client Authentication", null, "[\"email\",\"upn\"]", "ClientAuth", new DateTime(2026, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), null },
                    { new Guid("00000000-0000-0000-0000-000000000005"), new DateTime(2026, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, "Intermediate CA certificate signed by this root CA. Can issue and sign leaf certificates on behalf of the root. Sets BasicConstraints CA:TRUE and KeyCertSign.", "[]", true, null, null, "[\"KeyCertSign\",\"CrlSign\",\"DigitalSignature\"]", "Subordinate CA", null, "[]", "SubordinateCA", new DateTime(2026, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 3650 }
                });

            migrationBuilder.CreateIndex(
                name: "IX_AcmeAccounts_JwkThumbprint",
                table: "AcmeAccounts",
                column: "JwkThumbprint",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AcmeAuthorizations_OrderId",
                table: "AcmeAuthorizations",
                column: "OrderId");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeChallenges_AuthorizationId_Type",
                table: "AcmeChallenges",
                columns: new[] { "AuthorizationId", "Type" });

            migrationBuilder.CreateIndex(
                name: "IX_AcmeChallenges_Token",
                table: "AcmeChallenges",
                column: "Token",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AcmeExternalAccountKeys_Kid",
                table: "AcmeExternalAccountKeys",
                column: "Kid",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AcmeOrders_AccountId_Status",
                table: "AcmeOrders",
                columns: new[] { "AccountId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_AcmeOrders_CertificateRequestId",
                table: "AcmeOrders",
                column: "CertificateRequestId");

            migrationBuilder.CreateIndex(
                name: "IX_ApprovalRequests_RequestedBySubject_Operation_TargetId_Status",
                table: "ApprovalRequests",
                columns: new[] { "RequestedBySubject", "Operation", "TargetId", "Status" });

            migrationBuilder.CreateIndex(
                name: "UX_ApprovalRequests_OpenPerKey",
                table: "ApprovalRequests",
                columns: new[] { "RequestedBySubject", "Operation", "TargetId" },
                unique: true,
                filter: "\"TargetId\" IS NOT NULL AND \"Status\" IN ('Pending', 'Approved')");

            migrationBuilder.CreateIndex(
                name: "IX_BackgroundJobs_ConcurrencyKey",
                table: "BackgroundJobs",
                column: "ConcurrencyKey",
                unique: true,
                filter: "\"ConcurrencyKey\" IS NOT NULL AND \"Status\" IN ('Pending', 'Processing')");

            migrationBuilder.CreateIndex(
                name: "IX_BackgroundJobs_Status_NextAttemptAfterUtc",
                table: "BackgroundJobs",
                columns: new[] { "Status", "NextAttemptAfterUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_BulkOperationItems_OperationId_Outcome",
                table: "BulkOperationItems",
                columns: new[] { "OperationId", "Outcome" });

            migrationBuilder.CreateIndex(
                name: "IX_BulkOperations_Status_CreatedAtUtc",
                table: "BulkOperations",
                columns: new[] { "Status", "CreatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_CertificateNotes_RequestId_CreatedAtUtc",
                table: "CertificateNotes",
                columns: new[] { "RequestId", "CreatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_CertificateRequests_CommonName_Active",
                table: "CertificateRequests",
                column: "CommonName",
                unique: true,
                filter: "\"Status\" NOT IN ('Rejected', 'Revoked') AND (\"Type\" IS NULL OR \"Type\" <> 'RootCA') AND \"RenewedFromId\" IS NULL");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateRequests_IssuerId_Status",
                table: "CertificateRequests",
                columns: new[] { "IssuerId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_CertificateRequests_PolicyVersionId",
                table: "CertificateRequests",
                column: "PolicyVersionId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateRequests_PqcSerialNumber",
                table: "CertificateRequests",
                column: "PqcSerialNumber",
                unique: true,
                filter: "\"PqcSerialNumber\" IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateRequests_RenewedFromId_Status",
                table: "CertificateRequests",
                columns: new[] { "RenewedFromId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_CertificateRequests_SerialNumber",
                table: "CertificateRequests",
                column: "SerialNumber",
                unique: true,
                filter: "\"SerialNumber\" IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateRequests_Status_CreatedAtUtc",
                table: "CertificateRequests",
                columns: new[] { "Status", "CreatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_CertificateRequests_Status_Id",
                table: "CertificateRequests",
                columns: new[] { "Status", "Id" });

            migrationBuilder.CreateIndex(
                name: "IX_CertificateTemplates_IssuancePolicyId",
                table: "CertificateTemplates",
                column: "IssuancePolicyId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateTemplates_TypeKey",
                table: "CertificateTemplates",
                column: "TypeKey",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_EstEnrollmentCredentials_Username",
                table: "EstEnrollmentCredentials",
                column: "Username",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_IssuancePolicies_Name",
                table: "IssuancePolicies",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_IssuancePolicyVersions_OneDraft",
                table: "IssuancePolicyVersions",
                column: "PolicyId",
                unique: true,
                filter: "\"Status\" = 'Draft'");

            migrationBuilder.CreateIndex(
                name: "IX_IssuancePolicyVersions_OnePublished",
                table: "IssuancePolicyVersions",
                column: "PolicyId",
                unique: true,
                filter: "\"Status\" = 'Published'");

            migrationBuilder.CreateIndex(
                name: "IX_IssuancePolicyVersions_PolicyId_VersionNumber",
                table: "IssuancePolicyVersions",
                columns: new[] { "PolicyId", "VersionNumber" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Issuers_IsDefault",
                table: "Issuers",
                column: "IsDefault",
                unique: true,
                filter: "\"IsDefault\" = 1");

            migrationBuilder.CreateIndex(
                name: "IX_Issuers_Name",
                table: "Issuers",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Issuers_ParentIssuerId",
                table: "Issuers",
                column: "ParentIssuerId");

            migrationBuilder.CreateIndex(
                name: "IX_Issuers_SpkiSha256",
                table: "Issuers",
                column: "SpkiSha256",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_LifecycleEvents_Kind_OccurredAtUtc",
                table: "LifecycleEvents",
                columns: new[] { "Kind", "OccurredAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_LifecycleEvents_SubjectType_SubjectId_OccurredAtUtc",
                table: "LifecycleEvents",
                columns: new[] { "SubjectType", "SubjectId", "OccurredAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_Notices_RequestId_Kind_Step",
                table: "Notices",
                columns: new[] { "RequestId", "Kind", "Step" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Notices_Status_CreatedAtUtc",
                table: "Notices",
                columns: new[] { "Status", "CreatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_PqcExceptions_TemplateTypeKey_ExpiresAtUtc",
                table: "PqcExceptions",
                columns: new[] { "TemplateTypeKey", "ExpiresAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_RolePermissions_Role_Permission",
                table: "RolePermissions",
                columns: new[] { "Role", "Permission" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_WebhookDeliveries_Status_NextAttemptAfterUtc",
                table: "WebhookDeliveries",
                columns: new[] { "Status", "NextAttemptAfterUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_WebhookDeliveries_WebhookId",
                table: "WebhookDeliveries",
                column: "WebhookId");

            migrationBuilder.CreateIndex(
                name: "IX_WebhookDestinationRules_Source_StableKey",
                table: "WebhookDestinationRules",
                columns: new[] { "Source", "StableKey" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Webhooks_IsEnabled",
                table: "Webhooks",
                column: "IsEnabled");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AcmeChallenges");

            migrationBuilder.DropTable(
                name: "AcmeExternalAccountKeys");

            migrationBuilder.DropTable(
                name: "ApprovalRequests");

            migrationBuilder.DropTable(
                name: "BackgroundJobs");

            migrationBuilder.DropTable(
                name: "BulkOperationItems");

            migrationBuilder.DropTable(
                name: "CertificateNotes");

            migrationBuilder.DropTable(
                name: "CertificateRequests");

            migrationBuilder.DropTable(
                name: "CertificateTemplates");

            migrationBuilder.DropTable(
                name: "EstEnrollmentCredentials");

            migrationBuilder.DropTable(
                name: "Issuers");

            migrationBuilder.DropTable(
                name: "LifecycleEvents");

            migrationBuilder.DropTable(
                name: "Notices");

            migrationBuilder.DropTable(
                name: "ObservedRoles");

            migrationBuilder.DropTable(
                name: "PqcExceptions");

            migrationBuilder.DropTable(
                name: "RolePermissions");

            migrationBuilder.DropTable(
                name: "Settings");

            migrationBuilder.DropTable(
                name: "WebhookDeliveries");

            migrationBuilder.DropTable(
                name: "WebhookDestinationPolicyStates");

            migrationBuilder.DropTable(
                name: "WebhookDestinationRules");

            migrationBuilder.DropTable(
                name: "AcmeAuthorizations");

            migrationBuilder.DropTable(
                name: "BulkOperations");

            migrationBuilder.DropTable(
                name: "IssuancePolicyVersions");

            migrationBuilder.DropTable(
                name: "Webhooks");

            migrationBuilder.DropTable(
                name: "AcmeOrders");

            migrationBuilder.DropTable(
                name: "IssuancePolicies");

            migrationBuilder.DropTable(
                name: "AcmeAccounts");
        }
    }
}
