using Qertum.Cli.Doctor;

namespace Qertum.Tests.Cli.Doctor;

public sealed class OsRootStoreTests
{
    [Fact]
    public void AFingerprintNoStoreHolds_IsNeverReportedInstalled_AndNeverThrows()
    {
        var answer = new OsRootStore().Lookup(new string('0', 64));

        Assert.NotEqual(RootStoreAnswer.Installed, answer);
    }
}
