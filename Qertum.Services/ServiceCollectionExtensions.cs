using Qertum.Services.Issuers;
using System.Diagnostics.Metrics;
using Qertum.Services.Validators;
using FluentValidation;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Qertum.Services.DataProtection;
using Qertum.ServiceDefaults.Secrets;
using Qertum.Services.Webhooks;

namespace Qertum.Services;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddCustomCaServices(this IServiceCollection services, string? certificateRequestsConnectionString = null, string? environmentName = null)
    {
        var effectiveConnectionString = GetCertificateRequestsConnectionString(certificateRequestsConnectionString, environmentName);

        // Persist data-protection keys beside the DB so both ApiService and
        // QueueConsumer share the same key ring and can decrypt each other's data.
        var keysDirectory = new DirectoryInfo(GetDataProtectionKeysDirectory(effectiveConnectionString));
        keysDirectory.Create();
        var sharedDataDirectory = keysDirectory.Parent!.FullName;
        services.AddSingleton(new SecretStorageOptions { DataDirectory = sharedDataDirectory });

        var secretProtector = SecretProtectorFactory.Create(sharedDataDirectory);
        services.AddDataProtection()
            .PersistKeysToFileSystem(keysDirectory)
            .SetApplicationName("Qertum")
            .ProtectKeysWithSecretProtector(secretProtector);

        // CA key/cert live beside the DB for the same reason — both services must
        // resolve to the same physical directory so they share one root CA.
        var caDataDir = GetCaDataDirectory(effectiveConnectionString);
        Directory.CreateDirectory(caDataDir);
        services.AddSingleton(new CaDataOptions { Directory = caDataDir });

        // Audit log: default path is beside the DB so both ApiService and QueueConsumer
        // resolve to the same directory automatically. Override via AuditLog:File:Path.
        var defaultAuditPath = GetDefaultAuditLogPath(effectiveConnectionString);
        Directory.CreateDirectory(Path.GetDirectoryName(defaultAuditPath)!);
        services.AddOptions<AuditLogOptions>()
            .BindConfiguration(AuditLogOptions.SectionName)
            .PostConfigure(opts =>
            {
                if (string.IsNullOrEmpty(opts.File.Path))
                    opts.File.Path = defaultAuditPath;
            });

        services.AddOptions<Lifecycle.LifecycleEventsOptions>()
            .BindConfiguration(Lifecycle.LifecycleEventsOptions.SectionName)
            .Validate(o => o.DiagnosticRetentionDays >= 1, "LifecycleEvents:DiagnosticRetentionDays must be at least 1.")
            .Validate(o => o.BufferingTimeLimitMs is >= 10 and <= 60_000, "LifecycleEvents:BufferingTimeLimitMs must be between 10 and 60000.")
            .ValidateOnStart();

        services.AddOptions<Enrollment.EnrollmentOptions>().BindConfiguration(Enrollment.EnrollmentOptions.SectionName);
        services.AddSingleton<Enrollment.EnrollmentDisplayUrls>();

        services.AddMemoryCache();

        services.AddDbContext<CertificateRequestDbContext>(options =>
            options.UseSqlite(effectiveConnectionString));

        services.AddSingleton<IValidator<CreateCertificateRequestRequest>, CreateCertificateRequestValidator>();
        services.AddSingleton<IValidator<CertificateMetadata>, CertificateMetadataValidator>();
        services.AddSingleton<IValidator<SaveCertificateNoteRequest>, SaveCertificateNoteRequestValidator>();
        services.AddSingleton<IValidator<UpdateCertificateRequestRequest>, UpdateCertificateRequestValidator>();
        services.AddSingleton<IValidator<CaSettings>, CaSettingsValidator>();
        services.AddSingleton<IValidator<GenerateCaRequest>, GenerateCaRequestValidator>();
        services.AddSingleton<IValidator<ImportCaRequest>, ImportCaRequestValidator>();
        services.AddSingleton<IValidator<SaveCertificateTemplateRequest>, SaveCertificateTemplateRequestValidator>();
        services.AddSingleton<IValidator<SaveWebhookRequest>, SaveWebhookRequestValidator>();
        services.AddSingleton<IValidator<CreateEstEnrollmentCredentialRequest>, CreateEstEnrollmentCredentialRequestValidator>();
        services.AddSingleton<IValidator<SaveIssuancePolicyRequest>, SaveIssuancePolicyRequestValidator>();
        services.AddSingleton<IValidator<SaveIssuancePolicyDraftRequest>, SaveIssuancePolicyDraftRequestValidator>();
        services.AddSingleton<IValidator<PreviewBulkOperationRequest>, PreviewBulkOperationRequestValidator>();
        services.AddSingleton<IValidator<ExecuteBulkOperationRequest>, ExecuteBulkOperationRequestValidator>();

        services.AddScoped<ICertificateRequestService, CertificateRequestService>();
        services.AddScoped<CertificateInventoryService>();
        services.AddScoped<IPqcMigrationReportService, PqcMigrationReportService>();
        services.AddScoped<IWebhookService, WebhookService>();
        services.AddScoped<Notices.INoticeQueryService, Notices.NoticeQueryService>();
        services.AddScoped<CertificateNotes.ICertificateNoteService, CertificateNotes.CertificateNoteService>();
        services.AddScoped<IWebhookDestinationPolicyService, WebhookDestinationPolicyService>();
        services.AddScoped<ICertificateTemplateService, CertificateTemplateService>();
        services.AddSingleton<ICertificateGenerator, CertificateGenerator>();
        services.AddIssuerRegistry();
        services.AddSingleton<Policies.IIssuancePolicyEvaluator, Policies.IssuancePolicyEvaluator>();
        services.AddScoped<Policies.IIssuancePolicyService, Policies.IssuancePolicyService>();
        services.AddScoped<Policies.ICallerContextResolver, Policies.CallerContextResolver>();
        services.TryAddScoped<IPqcStageService, PqcStageService>();
        services.TryAddScoped<IPqcExceptionService, PqcExceptionService>();
        services.AddSingleton<IValidator<CreatePqcExceptionRequest>, CreatePqcExceptionRequestValidator>();
        services.AddPqcExceptionOptions();
        services.AddScoped<Policies.IIssuancePolicyManagementService, Policies.IssuancePolicyManagementService>();
        services.AddScoped<Policies.ICertificateRequestPreviewService, Policies.CertificateRequestPreviewService>();
        services.AddScoped<Enrollment.IEnrollmentOptionsService, Enrollment.EnrollmentOptionsService>();
        services.AddScoped<Dashboard.IAttentionService, Dashboard.AttentionService>();
        services.AddScoped<Recovery.IRecoveryStatusService, Recovery.RecoveryStatusService>();
        services.AddScoped<Lifecycle.ICertificateTimelineService, Lifecycle.CertificateTimelineService>();
        services.AddScoped<Acme.IAcmeOrderQueryService, Acme.AcmeOrderQueryService>();
        services.AddScoped<Est.IEstCredentialActivityService, Est.EstCredentialActivityService>();
        // First TimeProvider use in the repo; TryAdd so hosts and tests can replace it.
        services.TryAddSingleton(TimeProvider.System);
        services.AddScoped<IRolePermissionService, RolePermissionService>();
        services.AddScoped<Auth.IObservedRoleRecorder, Auth.ObservedRoleRecorder>();
        services.AddScoped<Auth.IRoleAccessService, Auth.RoleAccessService>();
        services.AddScoped<Acme.IAcmeExternalAccountKeyService, Acme.AcmeExternalAccountKeyService>();
        services.AddScoped<Est.IEstEnrollmentCredentialService, Est.EstEnrollmentCredentialService>();
        services.AddSingleton<AuditLogFileReader>();
        services.AddSingleton<AuditCheckpointReader>();
        services.AddSingleton(sp => new Qertum.Audit.AuditChain(
            Qertum.Audit.AuditChain.DefaultWriter(),
            Qertum.Audit.AuditLogFiles.NewestFirst(sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AuditLogOptions>>().Value.File.Path),
            sp.GetRequiredService<TimeProvider>()));
        // One instance behind both interfaces, so the audit and diagnostic loggers share one table sink.
        services.AddSingleton<SerilogAuditLogService>();
        services.AddSingleton<IAuditLogService>(sp => sp.GetRequiredService<SerilogAuditLogService>());
        services.AddSingleton<Lifecycle.IDiagnosticEventLog>(sp => sp.GetRequiredService<SerilogAuditLogService>());
        services.AddScoped<CertificateRequestApiService>();
        services.AddScoped<CertificateTemplateApiService>();
        services.AddScoped<RolePermissionsApiService>();
        services.AddScoped<AuditLogApiService>();

        services.AddSingleton<ICertificateApprovalQueue, CertificateApprovalChannel>();
        services.AddSingleton<ICertificateRevocationQueue, CertificateRevocationChannel>();
        services.TryAddScoped<BackgroundJobs.IBackgroundJobQueue, BackgroundJobs.BackgroundJobQueue>();
        services.TryAddSingleton<BackgroundJobs.IBackgroundJobSignal, BackgroundJobs.BackgroundJobChannel>();
        services.TryAddScoped<CrlPublisher>();


        return services;
    }

    /// <summary>
    /// Adds health checks shared by both ApiService and QueueConsumer:
    /// SQLite database connectivity and CA file presence.
    /// </summary>
    public static IHealthChecksBuilder AddCustomCaHealthChecks(this IHealthChecksBuilder builder)
    {
        return builder
            .AddCheck<DatabaseHealthCheck>("database", tags: ["ready"])
            .AddCheck<CaFilesHealthCheck>("ca-files", tags: ["ready"]);
    }

    /// <summary>
    /// Registers <see cref="CertificateQueueMetrics"/> and <see cref="OperationsMetrics"/> as singletons.
    /// Call this only in the QueueConsumer host — not in the API or Web hosts.
    /// </summary>
    public static IServiceCollection AddQueueConsumerMetrics(this IServiceCollection services)
    {
        // The gauges read the clock; TryAdd so a host or test that registered its own keeps it.
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(sp =>
        {
            var scopeFactory = sp.GetRequiredService<IServiceScopeFactory>();
            var clock = sp.GetRequiredService<TimeProvider>();
            return new OperationsMetrics(
                sp.GetRequiredService<IMeterFactory>(),
                OperationsProbes.OldestCrlAgeSeconds(scopeFactory, clock),
                OperationsProbes.ExpiringCertificates(scopeFactory, clock));
        });
        services.AddSingleton<CertificateQueueMetrics>(sp =>
        {
            var meterFactory = sp.GetRequiredService<IMeterFactory>();
            var scopeFactory = sp.GetRequiredService<IServiceScopeFactory>();
            var clock = sp.GetRequiredService<TimeProvider>();

            return new CertificateQueueMetrics(
                meterFactory,
                queueDepthProvider:   () => QueryCount(db => db.CertificateRequests.Count(r => r.Status == CertificateRequestStatus.Approved)),
                activeCertsProvider:  () => QueryCount(db => db.CertificateRequests.Count(r => r.Status == CertificateRequestStatus.Issued && (r.ValidTo == null || r.ValidTo > clock.GetUtcNow().UtcDateTime))),
                expiredCertsProvider: () => QueryCount(db => db.CertificateRequests.Count(r => r.Status == CertificateRequestStatus.Issued && r.ValidTo != null && r.ValidTo <= clock.GetUtcNow().UtcDateTime)),
                revokedCertsProvider: () => QueryCount(db => db.CertificateRequests.Count(r => r.Status == CertificateRequestStatus.Revoked)));

            // All observable gauge callbacks are invoked by the OTel SDK on its own schedule.
            // We open a short-lived scope each time so we never hold a long-lived DbContext.
            int QueryCount(Func<CertificateRequestDbContext, int> query)
            {
                try
                {
                    using var scope = scopeFactory.CreateScope();
                    var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
                    return query(db);
                }
                catch
                {
                    return 0;
                }
            }
        });

        return services;
    }

    private static string GetCertificateRequestsConnectionString(string? certificateRequestsConnectionString, string? environmentName)
    {
        if (!string.IsNullOrWhiteSpace(certificateRequestsConnectionString))
            return certificateRequestsConnectionString;

        // In non-Development environments, require an explicit connection string rather
        // than silently falling back to a LocalApplicationData path that may not exist
        // or may not be accessible.
        var env = environmentName
                  ?? Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT")
                  ?? Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT");
        if (!string.IsNullOrEmpty(env) &&
            !string.Equals(env, "Development", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(env, "Test", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "ConnectionStrings__CertificateRequests must be set in non-Development environments. " +
                "Set the connection string via configuration or the ASPNETCORE_CONNECTIONSTRINGS__CERTIFICATEREQUESTS environment variable.");
        }

        var dataDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Qertum");

        Directory.CreateDirectory(dataDirectory);

        return $"Data Source={Path.Combine(dataDirectory, "certificate-requests.db")}";
    }

    /// <summary>
    /// Derives the data-protection key storage directory from the SQLite connection string
    /// so that all services sharing the same database also share the same key ring.
    /// </summary>
    private static string GetDataProtectionKeysDirectory(string connectionString)
    {
        var dataSource = connectionString
            .Split(';', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Trim())
            .FirstOrDefault(part => part.StartsWith("Data Source=", StringComparison.OrdinalIgnoreCase));

        if (dataSource is not null)
        {
            var dbPath = dataSource["Data Source=".Length..].Trim();
            var dbDir = Path.GetDirectoryName(dbPath);
            if (!string.IsNullOrEmpty(dbDir))
                return Path.Combine(dbDir, "DataProtection-Keys");
        }

        // Fallback: same LocalAppData folder used by the standalone connection string.
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Qertum", "DataProtection-Keys");
    }

    /// <summary>
    /// Derives the CA data directory from the SQLite connection string so that all
    /// services sharing the same database also share the same root CA keypair.
    /// </summary>
    private static string GetCaDataDirectory(string connectionString)
    {
        var dataSource = connectionString
            .Split(';', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Trim())
            .FirstOrDefault(part => part.StartsWith("Data Source=", StringComparison.OrdinalIgnoreCase));

        if (dataSource is not null)
        {
            var dbPath = dataSource["Data Source=".Length..].Trim();
            var dbDir = Path.GetDirectoryName(dbPath);
            if (!string.IsNullOrEmpty(dbDir))
                return Path.Combine(dbDir, "CaData");
        }

        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Qertum", "CaData");
    }

    /// <summary>
    /// Derives the default audit log file path from the SQLite connection string so that both
    /// ApiService and QueueConsumer share the same audit log directory without explicit config.
    /// The date suffix and extension are appended by Serilog's rolling file sink.
    /// </summary>
    private static string GetDefaultAuditLogPath(string connectionString)
    {
        var dataSource = connectionString
            .Split(';', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Trim())
            .FirstOrDefault(part => part.StartsWith("Data Source=", StringComparison.OrdinalIgnoreCase));

        if (dataSource is not null)
        {
            var dbPath = dataSource["Data Source=".Length..].Trim();
            var dbDir = Path.GetDirectoryName(dbPath);
            if (!string.IsNullOrEmpty(dbDir))
                return Path.Combine(dbDir, "audit-logs", "audit-.clef");
        }

        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Qertum", "audit-logs", "audit-.clef");
    }
}
