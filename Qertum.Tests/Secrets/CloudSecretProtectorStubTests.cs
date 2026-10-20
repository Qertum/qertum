using Qertum.ServiceDefaults.Secrets;

namespace Qertum.Tests.Secrets;

public sealed class CloudSecretProtectorStubTests
{
    [Fact]
    public void Protect_ThrowsNotSupported()
    {
        var stub = new CloudSecretProtectorStub();
        Assert.Throws<NotSupportedException>(() => stub.Protect("x"u8.ToArray()));
    }

    [Fact]
    public void Unprotect_ThrowsNotSupported()
    {
        var stub = new CloudSecretProtectorStub();
        Assert.Throws<NotSupportedException>(() => stub.Unprotect("x"u8.ToArray()));
    }
}
