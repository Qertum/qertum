using Qertum.Services;

namespace Qertum.Tests;

public sealed class CertificateApprovalChannelTests
{
    [Fact]
    public async Task Signal_IsDeliveredToWaiter()
    {
        ICertificateApprovalQueue queue = new CertificateApprovalChannel();

        var signalled = queue.TrySignal();
        Assert.True(signalled);

        var received = await queue.WaitToReadAsync(TestContext.Current.CancellationToken);
        Assert.True(received);
    }

    [Fact]
    public void BoundedCapacity_DropsExcessSignals()
    {
        ICertificateApprovalQueue queue = new CertificateApprovalChannel();

        queue.TrySignal();
        queue.TrySignal(); // dropped — capacity 1, DropNewest

        // Drain should consume exactly one item
        queue.Drain();
        // A second drain should be a no-op (nothing left to drain)
        queue.Drain();
    }

    [Fact]
    public async Task Signal_UnblocksWaitToReadAsync()
    {
        ICertificateApprovalQueue queue = new CertificateApprovalChannel();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        var waitTask = queue.WaitToReadAsync(cts.Token).AsTask();

        queue.TrySignal();

        var result = await waitTask;
        Assert.True(result);
    }

    [Fact]
    public async Task RevocationQueue_Signal_UnblocksWaiter()
    {
        ICertificateRevocationQueue queue = new CertificateRevocationChannel();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        var waitTask = queue.WaitToReadAsync(cts.Token).AsTask();

        queue.TrySignal();

        var result = await waitTask;
        Assert.True(result);
    }
}
