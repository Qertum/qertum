using Bunit;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Enrollment;

/// <summary>
/// Enrollment options hide templates the caller's roles may not request, so an empty list for a
/// non-admin means "nothing for you", not "nothing configured".
/// </summary>
public sealed class WizardTemplateAvailabilityTests
{
    [Fact]
    public async Task NoTemplates_ForANonAdmin_SaysNoneAreAvailableToTheirRoles()
    {
        await using var host = new WizardTestHost();
        host.Api.Options = new EnrollmentOptionsResponse { Templates = [], Purposes = [] };

        var cut = host.Context.Render<NewCertificateRequest>();

        cut.WaitForAssertion(() => Assert.Contains(
            "No certificate templates are available to your roles; ask an administrator.", cut.Markup));
        Assert.DoesNotContain("certificate-templates/new", cut.Markup);
    }
}
