using System.Threading.Channels;

namespace Qertum.Services.BackgroundJobs;

/// <summary>In-process wake-up for the background job processor after a producer enqueues.</summary>
public interface IBackgroundJobSignal
{
    /// <summary>Wakes the processor; a signal already waiting absorbs this one.</summary>
    bool TrySignal();

    /// <summary>Completes when a signal is waiting.</summary>
    ValueTask<bool> WaitToReadAsync(CancellationToken cancellationToken);

    /// <summary>Discards waiting signals.</summary>
    void Drain();
}

/// <summary>Bounded single-slot channel, same shape as <see cref="CertificateApprovalChannel"/>.</summary>
public sealed class BackgroundJobChannel : IBackgroundJobSignal
{
    private readonly Channel<bool> _channel = Channel.CreateBounded<bool>(
        new BoundedChannelOptions(1)
        {
            FullMode = BoundedChannelFullMode.DropNewest,
            SingleWriter = false,
            SingleReader = true
        });

    /// <inheritdoc/>
    public bool TrySignal() => _channel.Writer.TryWrite(true);

    /// <inheritdoc/>
    public ValueTask<bool> WaitToReadAsync(CancellationToken cancellationToken) =>
        _channel.Reader.WaitToReadAsync(cancellationToken);

    /// <inheritdoc/>
    public void Drain() { while (_channel.Reader.TryRead(out _)) { } }
}
