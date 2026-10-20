using System.Text.Json.Serialization;
namespace Qertum.Services;

/// <summary>
/// How strictly a template (or the CA as a whole) treats classical RSA and ECDSA subject keys.
/// Stored and serialized as the name. Compliant algorithms (PQC, hybrid, composite, ML-KEM) are
/// allowed at every stage.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum PqcStage
{
    /// <summary>Classical keys are allowed and nothing is recorded.</summary>
    Off,
    /// <summary>Classical keys are allowed; a diagnostic event is recorded.</summary>
    Observe,
    /// <summary>Classical keys are allowed; the requester is warned and an event is recorded.</summary>
    Warn,
    /// <summary>New requests with a classical key are refused; renewals are allowed with a warning.</summary>
    Pilot,
    /// <summary>Every request with a classical key is refused.</summary>
    Enforce
}
