using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

internal sealed partial class PolicyTestDb
{
    public IssuancePolicyManagementService CreateManagementService(IWebhookService? webhooks = null) =>
        new(Db, Audit, webhooks ?? CreateWebhookService());
}
