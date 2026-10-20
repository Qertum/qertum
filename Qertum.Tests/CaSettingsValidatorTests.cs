using Qertum.Services;
using Qertum.Services.Validators;

namespace Qertum.Tests;

/// <summary>
/// The ACME challenge allowlist is stored as a JSON array of CIDR strings. Rejecting malformed
/// entries on save is what lets the address policy ignore them at connect time instead of failing
/// the whole list closed.
/// </summary>
public sealed class CaSettingsValidatorTests
{
    private static readonly CaSettingsValidator Validator = new();

    private static CaSettings WithNetworks(string? json) => new()
    {
        OrganizationName = "Contoso",
        AcmeChallengeAllowedNetworksJson = json
    };

    [Fact]
    public void AcceptsAnAbsentAllowlist()
    {
        // Null is the post-upgrade default: no ACME challenge validates until configured, which is
        // a deliberate operational state, not a validation error.
        Assert.True(Validator.Validate(WithNetworks(null)).IsValid);
    }

    [Fact]
    public void AcceptsValidCidrEntries()
    {
        var result = Validator.Validate(WithNetworks("""["10.1.0.0/16","192.168.4.0/24","fd00::/8"]"""));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void RejectsAMalformedCidrAndNamesTheOffendingEntry()
    {
        var result = Validator.Validate(WithNetworks("""["10.1.0.0/16","not-a-cidr"]"""));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.ErrorMessage.Contains("not-a-cidr"));
    }

    [Fact]
    public void RejectsAnOutOfRangePrefixLength()
    {
        var result = Validator.Validate(WithNetworks("""["10.0.0.0/99"]"""));

        Assert.False(result.IsValid);
    }

    [Fact]
    public void RejectsMalformedJson()
    {
        var result = Validator.Validate(WithNetworks("{not json"));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.ErrorMessage.Contains("JSON array"));
    }

    [Fact]
    public void RejectsMoreEntriesThanTheCap()
    {
        var entries = Enumerable.Range(0, 51).Select(i => $"\"10.{i}.0.0/16\"");
        var result = Validator.Validate(WithNetworks($"[{string.Join(',', entries)}]"));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.ErrorMessage.Contains("At most 50"));
    }

    [Fact]
    public void RejectsANonAbsoluteCrlDeltaDistributionPoint()
    {
        var result = Validator.Validate(new CaSettings { PqcStage = PqcStage.Off, CrlDeltaDistributionPoint = "not-a-url" });

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.PropertyName == nameof(CaSettings.CrlDeltaDistributionPoint));
    }

    [Fact]
    public void RejectsAZeroDeltaCrlValidityHours()
    {
        var result = Validator.Validate(new CaSettings { PqcStage = PqcStage.Off, DeltaCrlValidityHours = 0 });

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.PropertyName == nameof(CaSettings.DeltaCrlValidityHours));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void RejectsANonPositivePendingApprovalAge(int hours)
    {
        var settings = new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Contoso", AttentionPendingApprovalAgeHours = hours };

        var result = Validator.Validate(settings);

        Assert.Contains(result.Errors, e => e.PropertyName == nameof(CaSettings.AttentionPendingApprovalAgeHours));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void RejectsANonPositiveFailureLookback(int days)
    {
        var settings = new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Contoso", AttentionFailureLookbackDays = days };

        var result = Validator.Validate(settings);

        Assert.Contains(result.Errors, e => e.PropertyName == nameof(CaSettings.AttentionFailureLookbackDays));
    }

    [Fact]
    public void AttentionThresholdDefaultsAreValid()
    {
        var settings = new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Contoso" };

        Assert.Equal(72, settings.AttentionPendingApprovalAgeHours);
        Assert.Equal(7, settings.AttentionFailureLookbackDays);
        Assert.True(Validator.Validate(settings).IsValid);
    }

    [Theory]
    [InlineData("https://ca.example.com")]
    [InlineData("http://10.0.0.5:8080/")]
    public void PublicBaseUrl_AcceptsAbsoluteHttpUrls(string url)
    {
        var result = Validator.Validate(new CaSettings { PqcStage = PqcStage.Off, PublicBaseUrl = url });
        Assert.DoesNotContain(result.Errors, e => e.PropertyName == nameof(CaSettings.PublicBaseUrl));
    }

    [Theory]
    [InlineData("ca.example.com")]
    [InlineData("ftp://ca.example.com")]
    [InlineData("https://ca.example.com/?q=1")]
    public void PublicBaseUrl_RefusesRelativeNonHttpOrQueryUrls(string url)
    {
        var result = Validator.Validate(new CaSettings { PqcStage = PqcStage.Off, PublicBaseUrl = url });
        Assert.Contains(result.Errors, e => e.PropertyName == nameof(CaSettings.PublicBaseUrl));
    }

    [Fact]
    public void RecoveryThresholdDefaultsAreValid()
    {
        var settings = new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Contoso" };

        Assert.Equal(48, settings.AttentionBackupMaxAgeHours);
        Assert.Equal(35, settings.AttentionRestoreVerifiedMaxAgeDays);
        Assert.True(Validator.Validate(settings).IsValid);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void RecoveryThresholds_MustBePositive(int value)
    {
        var backup = Validator.Validate(new CaSettings { PqcStage = PqcStage.Off, AttentionBackupMaxAgeHours = value });
        var restore = Validator.Validate(new CaSettings { PqcStage = PqcStage.Off, AttentionRestoreVerifiedMaxAgeDays = value });

        Assert.Contains(backup.Errors, e => e.PropertyName == nameof(CaSettings.AttentionBackupMaxAgeHours));
        Assert.Contains(restore.Errors, e => e.PropertyName == nameof(CaSettings.AttentionRestoreVerifiedMaxAgeDays));
    }
}
