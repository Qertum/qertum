using Qertum.IdentityService.Services.Audit;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Qertum.IdentityService.Pages.Admin;

public sealed class AuditModel(IdentityAuditLogReader reader) : PageModel
{
    public const int PageSize = 50;

    /// <summary>1-based page number. Not called "page": Razor Pages reserves that route value.</summary>
    [BindProperty(SupportsGet = true, Name = "p")]
    public int PageNumber { get; set; } = 1;

    public IReadOnlyList<IdentityAuditEntry> Entries { get; private set; } = [];

    public bool HasOlder { get; private set; }

    [BindProperty(SupportsGet = true)]
    public string? Action { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? Actor { get; set; }

    [BindProperty(SupportsGet = true)]
    public DateOnly? From { get; set; }

    [BindProperty(SupportsGet = true)]
    public DateOnly? To { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? Text { get; set; }

    /// <summary>True when the scan stopped at the reader's cap before reaching the end of the log.</summary>
    public bool Truncated { get; private set; }

    /// <summary>Action names offered by the filter, straight from the constants.</summary>
    public IReadOnlyList<string> Actions => IdentityAuditActions.All;

    /// <summary>The current filter as a query string fragment, so paging links keep it.</summary>
    public string FilterQuery()
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(Action)) parts.Add("Action=" + Uri.EscapeDataString(Action));
        if (!string.IsNullOrWhiteSpace(Actor)) parts.Add("Actor=" + Uri.EscapeDataString(Actor));
        if (From is { } from) parts.Add("From=" + from.ToString("yyyy-MM-dd"));
        if (To is { } to) parts.Add("To=" + to.ToString("yyyy-MM-dd"));
        if (!string.IsNullOrWhiteSpace(Text)) parts.Add("Text=" + Uri.EscapeDataString(Text));
        return parts.Count == 0 ? string.Empty : "&" + string.Join("&", parts);
    }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        PageNumber = Math.Max(1, PageNumber);

        var page = await reader.ReadAsync(
            new IdentityAuditQuery(Action, Actor, From, To, Text), (PageNumber - 1) * PageSize, PageSize, cancellationToken);

        Entries = page.Entries;
        HasOlder = page.HasOlder;
        Truncated = page.Truncated;
    }
}
