using Qertum.Services;

namespace Qertum.Web.Auth;

/// <summary>Tells the circuit that the API refused an operation until the user signs in again with a second factor.</summary>
public interface IStepUpNotifier
{
    /// <summary>Raised when an API call is answered with an RFC 9470 step-up challenge.</summary>
    event Action<StepUpChallenge>? Required;

    /// <summary>Raises <see cref="Required"/>.</summary>
    /// <param name="challenge">What the API asked for.</param>
    void Raise(StepUpChallenge challenge);
}

/// <summary>The circuit-scoped <see cref="IStepUpNotifier"/>.</summary>
public sealed class StepUpNotifier : IStepUpNotifier
{
    /// <inheritdoc />
    public event Action<StepUpChallenge>? Required;

    /// <inheritdoc />
    public void Raise(StepUpChallenge challenge) => Required?.Invoke(challenge);
}
