using Microsoft.Extensions.Logging.Abstractions;
using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

internal sealed partial class PolicyTestDb
{
    /// <summary>A real webhook service over this database, so enqueued rows are observable.</summary>
    public WebhookService CreateWebhookService() => new(Db, NullLogger<WebhookService>.Instance);

    /// <summary>A request service whose webhook calls actually write delivery rows.</summary>
    public CertificateRequestService CreateRequestServiceWithWebhooks() =>
        new(Db, Audit, CreateWebhookService(), new IssuancePolicyService(Db, new IssuancePolicyEvaluator()));

    /// <summary>A template service wired to a real (or supplied) webhook service.</summary>
    public CertificateTemplateService CreateTemplateService(IWebhookService? webhooks = null) =>
        new(Db, Audit, webhooks ?? CreateWebhookService());
}
