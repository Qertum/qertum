namespace Qertum.IdentityService.Services.Audit;

public sealed record IdentityAuditEntry(
    Guid Id,
    DateTime OccurredAtUtc,
    string Action,
    string PerformedBy,
    Guid? ResourceId,
    string? ResourceName,
    string? Detail,
    string? TraceId);
