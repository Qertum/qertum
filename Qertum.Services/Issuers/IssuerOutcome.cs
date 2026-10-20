namespace Qertum.Services.Issuers;

/// <summary>Why an issuer operation was refused.</summary>
public enum IssuerRefusal
{
    /// <summary>The issuer (or a named parent) does not exist.</summary>
    NotFound,

    /// <summary>The issuer's state forbids the operation.</summary>
    Conflict,

    /// <summary>The input is invalid.</summary>
    Invalid
}

/// <summary>Result of an issuer operation: a value, or a refusal with its reason. Refusals never throw.</summary>
public sealed record IssuerOutcome<T>(T? Value, IssuerRefusal? Refusal, string? Message)
{
    public static IssuerOutcome<T> Ok(T value) => new(value, null, null);
    public static IssuerOutcome<T> NotFound(string message) => new(default, IssuerRefusal.NotFound, message);
    public static IssuerOutcome<T> Conflict(string message) => new(default, IssuerRefusal.Conflict, message);
    public static IssuerOutcome<T> Invalid(string message) => new(default, IssuerRefusal.Invalid, message);
}
