using System.Threading.Channels;

namespace Qertum.Services;

/// <summary>
/// In-process implementation of <see cref="ICertificateApprovalQueue"/> backed by a
/// bounded <see cref="Channel{T}"/>. Capacity 1 with DropNewest means a burst of
/// approvals still results in at most one wake signal outstanding.
/// </summary>
public sealed class CertificateApprovalChannel : ICertificateApprovalQueue
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
