namespace Qertum.Services;

/// <summary>
/// Abstraction over a work-signal queue that wakes the queue consumer on demand.
/// The default in-process implementation uses <see cref="System.Threading.Channels"/>;
/// replace with a durable message broker (Azure Service Bus, RabbitMQ, NATS) for
/// multi-instance, highly-available deployments.
/// </summary>
public interface ICertificateWorkQueue
{
    /// <summary>Signals that new work is available. Non-blocking and best-effort (a pending signal is not duplicated).</summary>
    bool TrySignal();

    /// <summary>Waits asynchronously until a signal is available or the token is cancelled.</summary>
    ValueTask<bool> WaitToReadAsync(CancellationToken cancellationToken);

    /// <summary>Drains any buffered signals after waking to prevent spurious re-entry.</summary>
    void Drain();
}

/// <summary>Signals the queue consumer when a certificate request is approved.</summary>
public interface ICertificateApprovalQueue : ICertificateWorkQueue;

/// <summary>Signals the queue consumer when a certificate revocation is queued.</summary>
public interface ICertificateRevocationQueue : ICertificateWorkQueue;
