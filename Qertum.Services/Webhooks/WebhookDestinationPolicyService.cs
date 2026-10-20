using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Webhooks;

/// <summary>Reads effective destination rules and reconciles the operator's JSON baseline.</summary>
public interface IWebhookDestinationPolicyService
{
    /// <summary>Returns an immutable snapshot, fail-closed until reconciliation completes.</summary>
    Task<WebhookDestinationPolicySnapshot> GetEffectiveAsync(CancellationToken cancellationToken = default);

    /// <summary>Atomically applies the API host's validated JSON policy baseline.</summary>
    Task ReconcileAsync(WebhookDestinationPolicyOptions options, CancellationToken cancellationToken = default);

    /// <summary>Sets the administrator's mode override; null restores the JSON mode.</summary>
    Task SetPublicModeAsync(WebhookPublicMode? mode, string actor, CancellationToken cancellationToken = default);

    /// <summary>Adds one administrator-owned destination rule.</summary>
    Task<WebhookDestinationRuleSnapshot> AddRuleAsync(SaveWebhookDestinationRuleRequest request, string actor, CancellationToken cancellationToken = default);

    /// <summary>Changes a rule's enabled state, or returns null when it is absent.</summary>
    Task<WebhookDestinationRuleSnapshot?> SetRuleEnabledAsync(Guid id, bool enabled, string actor, CancellationToken cancellationToken = default);

    /// <summary>Deletes an administrator rule, refusing configuration rules.</summary>
    Task<WebhookDestinationDeleteResult> DeleteAdminRuleAsync(Guid id, string actor, CancellationToken cancellationToken = default);

    /// <summary>Checks a saved URL's origin and literal IP, without a save-time DNS lookup.</summary>
    bool CanSaveUrl(WebhookDestinationPolicySnapshot snapshot, string rawUrl, out string? reason);
}

/// <summary>Outcome of a destination-rule delete operation.</summary>
public enum WebhookDestinationDeleteResult
{
    /// <summary>The administrator rule was removed.</summary>
    Deleted,
    /// <summary>No present rule has that identifier.</summary>
    NotFound,
    /// <summary>A configuration rule must be disabled or edited in JSON.</summary>
    ConfigurationRule
}

/// <summary>EF-backed webhook destination policy store.</summary>
public sealed class WebhookDestinationPolicyService(
    CertificateRequestDbContext db, IAuditLogService? auditLog = null, TimeProvider? timeProvider = null)
    : IWebhookDestinationPolicyService
{
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    /// <inheritdoc />
    public async Task<WebhookDestinationPolicySnapshot> GetEffectiveAsync(CancellationToken cancellationToken = default)
    {
        var state = await db.WebhookDestinationPolicyStates.AsNoTracking().SingleOrDefaultAsync(cancellationToken);
        if (state is not { Initialized: true })
            return new(false, WebhookPublicMode.AnyPublic, []);

        var rows = await db.WebhookDestinationRules.AsNoTracking()
            .Where(rule => rule.IsPresent)
            .OrderBy(rule => rule.Host).ThenBy(rule => rule.Port)
            .ToListAsync(cancellationToken);
        var rules = rows.Select(row => new WebhookDestinationRuleSnapshot(
            row.Id, row.Source, row.Kind, row.Scheme, row.Host, row.Port,
            row.Enabled && !row.AdminDisabled,
            JsonSerializer.Deserialize<string[]>(row.AllowedIpAddressesJson)!
                .Select(IPAddress.Parse).ToArray())).ToArray();
        return new(true, state.AdminPublicMode ?? state.JsonPublicMode, rules);
    }

    /// <inheritdoc />
    public async Task ReconcileAsync(WebhookDestinationPolicyOptions options, CancellationToken cancellationToken = default)
    {
        if (!WebhookDestinationPolicyOptions.IsValid(options))
            throw new ArgumentException("Webhook destination policy configuration is invalid.", nameof(options));

        var normalized = options.Rules.Select(rule =>
        {
            TryNormalize(rule, out var value);
            return value;
        }).ToArray();

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var state = await db.WebhookDestinationPolicyStates.SingleOrDefaultAsync(cancellationToken);
        if (state is null)
        {
            state = new WebhookDestinationPolicyState();
            db.WebhookDestinationPolicyStates.Add(state);
        }

        var existing = await db.WebhookDestinationRules
            .Where(rule => rule.Source == "Configuration")
            .ToListAsync(cancellationToken);
        foreach (var row in existing) row.IsPresent = false;
        foreach (var item in normalized)
        {
            var row = existing.SingleOrDefault(rule => rule.StableKey == item.StableKey);
            if (row is null)
            {
                row = new WebhookDestinationRule { Id = Guid.NewGuid(), Source = "Configuration", StableKey = item.StableKey };
                db.WebhookDestinationRules.Add(row);
            }
            row.Kind = item.Kind;
            row.Scheme = item.Scheme;
            row.Host = item.Host;
            row.Port = item.Port;
            row.AllowedIpAddressesJson = JsonSerializer.Serialize(item.Addresses);
            row.IsPresent = true;
            row.Enabled = true;
        }

        state.JsonPublicMode = options.PublicMode;
        state.Initialized = true;
        state.ReconciledAtUtc = _clock.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task SetPublicModeAsync(WebhookPublicMode? mode, string actor, CancellationToken cancellationToken = default)
    {
        if (mode.HasValue && !Enum.IsDefined(mode.Value))
            throw new ArgumentException("Unknown public-destination mode.", nameof(mode));
        var state = await RequireStateAsync(cancellationToken);
        if (state.AdminPublicMode == mode) return;
        state.AdminPublicMode = mode;
        await db.SaveChangesAsync(cancellationToken);
        if (auditLog is not null)
            await auditLog.LogAsync("WebhookDestinationModeUpdated", actor, detail: mode?.ToString() ?? "JSON default", cancellationToken: cancellationToken);
    }

    /// <inheritdoc />
    public async Task<WebhookDestinationRuleSnapshot> AddRuleAsync(
        SaveWebhookDestinationRuleRequest request, string actor, CancellationToken cancellationToken = default)
    {
        await RequireStateAsync(cancellationToken);
        if (!TryNormalize(new WebhookDestinationRuleOption
        {
            Kind = request.Kind, Scheme = request.Scheme, Host = request.Host, Port = request.Port,
            AllowedIpAddresses = request.AllowedIpAddresses
        }, out var normalized))
            throw new ArgumentException("Destination rule must name an exact HTTP(S) origin and valid IP pins.", nameof(request));

        var duplicate = await db.WebhookDestinationRules.AnyAsync(
            rule => rule.IsPresent && rule.StableKey == normalized.StableKey, cancellationToken);
        if (duplicate) throw new InvalidOperationException("Destination rule already exists.");

        var row = new WebhookDestinationRule
        {
            Id = Guid.NewGuid(), Source = "Admin", StableKey = normalized.StableKey,
            Kind = normalized.Kind, Scheme = normalized.Scheme, Host = normalized.Host, Port = normalized.Port,
            AllowedIpAddressesJson = JsonSerializer.Serialize(normalized.Addresses),
            IsPresent = true, Enabled = true
        };
        db.WebhookDestinationRules.Add(row);
        await db.SaveChangesAsync(cancellationToken);
        if (auditLog is not null)
            await auditLog.LogAsync("WebhookDestinationRuleAdded", actor, row.Id, row.Host,
                $"{row.Scheme}://{row.Host}:{row.Port} ({row.Kind})", cancellationToken);
        return ToSnapshot(row);
    }

    /// <inheritdoc />
    public async Task<WebhookDestinationRuleSnapshot?> SetRuleEnabledAsync(
        Guid id, bool enabled, string actor, CancellationToken cancellationToken = default)
    {
        await RequireStateAsync(cancellationToken);
        var row = await db.WebhookDestinationRules.SingleOrDefaultAsync(
            rule => rule.Id == id && rule.IsPresent, cancellationToken);
        if (row is null) return null;
        if (row.Source == "Configuration") row.AdminDisabled = !enabled;
        else row.Enabled = enabled;
        await db.SaveChangesAsync(cancellationToken);
        if (auditLog is not null)
            await auditLog.LogAsync("WebhookDestinationRuleToggled", actor, row.Id, row.Host,
                enabled ? "Enabled" : "Disabled", cancellationToken);
        return ToSnapshot(row);
    }

    /// <inheritdoc />
    public async Task<WebhookDestinationDeleteResult> DeleteAdminRuleAsync(
        Guid id, string actor, CancellationToken cancellationToken = default)
    {
        await RequireStateAsync(cancellationToken);
        var row = await db.WebhookDestinationRules.SingleOrDefaultAsync(
            rule => rule.Id == id && rule.IsPresent, cancellationToken);
        if (row is null) return WebhookDestinationDeleteResult.NotFound;
        if (row.Source != "Admin") return WebhookDestinationDeleteResult.ConfigurationRule;
        db.WebhookDestinationRules.Remove(row);
        await db.SaveChangesAsync(cancellationToken);
        if (auditLog is not null)
            await auditLog.LogAsync("WebhookDestinationRuleDeleted", actor, row.Id, row.Host,
                $"{row.Scheme}://{row.Host}:{row.Port}", cancellationToken);
        return WebhookDestinationDeleteResult.Deleted;
    }

    /// <inheritdoc />
    public bool CanSaveUrl(WebhookDestinationPolicySnapshot snapshot, string rawUrl, out string? reason)
    {
        reason = "Webhook destination is not allowed by policy.";
        if (!snapshot.Initialized || !WebhookDestinationTarget.TryParse(rawUrl, out var target, out _))
            return false;

        if (IPAddress.TryParse(target!.Host, out var literal))
        {
            var decision = WebhookAddressPolicy.Check(snapshot, target, [literal]);
            reason = decision.Reason;
            return decision.Allowed;
        }

        if (snapshot.PublicMode == WebhookPublicMode.AnyPublic)
        {
            reason = null;
            return true;
        }

        var listed = snapshot.Rules.Any(rule => rule.Enabled &&
            rule.Scheme.Equals(target.Scheme, StringComparison.OrdinalIgnoreCase) &&
            rule.Host.Equals(target.Host, StringComparison.OrdinalIgnoreCase) && rule.Port == target.Port);
        if (listed) reason = null;
        return listed;
    }

    private async Task<WebhookDestinationPolicyState> RequireStateAsync(CancellationToken cancellationToken)
        => await db.WebhookDestinationPolicyStates.SingleOrDefaultAsync(cancellationToken) is { Initialized: true } state
            ? state : throw new InvalidOperationException("Webhook destination policy is unavailable.");

    private static WebhookDestinationRuleSnapshot ToSnapshot(WebhookDestinationRule row)
        => new(row.Id, row.Source, row.Kind, row.Scheme, row.Host, row.Port,
            row.Enabled && !row.AdminDisabled,
            JsonSerializer.Deserialize<string[]>(row.AllowedIpAddressesJson)!.Select(IPAddress.Parse).ToArray());

    internal sealed record NormalizedRule(
        WebhookDestinationRuleKind Kind, string Scheme, string Host, int Port,
        string[] Addresses, string StableKey);

    internal static bool TryNormalize(WebhookDestinationRuleOption? rule, out NormalizedRule normalized)
    {
        normalized = null!;
        if (rule is null || !Enum.IsDefined(rule.Kind) || rule.Port is < 1 or > 65535 ||
            rule.AllowedIpAddresses is null || string.IsNullOrWhiteSpace(rule.Host) ||
            rule.Host.Contains('/') || rule.Host.Contains('?') || rule.Host.Contains('#')) return false;

        var hostForUri = rule.Host.Contains(':') && !rule.Host.StartsWith('[')
            ? $"[{rule.Host}]" : rule.Host;
        if (!WebhookDestinationTarget.TryParse($"{rule.Scheme}://{hostForUri}:{rule.Port}/", out var target, out _))
            return false;
        if (target is null) return false;

        var addresses = new List<string>();
        foreach (var raw in rule.AllowedIpAddresses)
        {
            if (!IPAddress.TryParse(raw, out var ip) ||
                ip.AddressFamily == AddressFamily.InterNetworkV6 && ip.ScopeId != 0 ||
                !WebhookAddressPolicy.IsEligibleInternalPin(ip)) return false;
            addresses.Add(ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : ip.ToString());
        }
        addresses.Sort(StringComparer.Ordinal);
        if (addresses.Count != addresses.Distinct(StringComparer.Ordinal).Count()) return false;
        if (rule.Kind == WebhookDestinationRuleKind.Internal && addresses.Count == 0 ||
            rule.Kind == WebhookDestinationRuleKind.Public && addresses.Count != 0) return false;

        var stableKey = $"{rule.Kind}|{target.Scheme}|{target.Host}|{target.Port}|{string.Join(',', addresses)}";
        normalized = new(rule.Kind, target.Scheme, target.Host, target.Port, [.. addresses], stableKey);
        return true;
    }
}
