namespace Qertum.Services;

/// <summary>Names for <see cref="CaSettings.RequireIndependentCaApproval"/> used in audit text, webhooks and the CLI.</summary>
public static class CaApprovalRule
{
    /// <summary>The approver must differ from the requester.</summary>
    public const string Independent = "independent";

    /// <summary>The requester may approve their own CA request; the approval audit says so.</summary>
    public const string Waived = "waived";

    /// <summary>The name of the mode a <see cref="CaSettings.RequireIndependentCaApproval"/> value means.</summary>
    public static string ModeName(bool requireIndependent) => requireIndependent ? Independent : Waived;

    /// <summary>Parses <c>independent</c> or <c>waived</c> (case-insensitive); anything else is false.</summary>
    public static bool TryParse(string? text, out bool requireIndependent)
    {
        requireIndependent = false;
        if (string.Equals(text, Independent, StringComparison.OrdinalIgnoreCase)) { requireIndependent = true; return true; }
        return string.Equals(text, Waived, StringComparison.OrdinalIgnoreCase);
    }
}
