using Qertum.Services;

namespace Qertum.Tests.Audit;

/// <summary>
/// Audit names and details can come from request bodies (an approval's target, a certificate name), so the audit
/// service writes each as one line: a value cannot forge what looks like a second log entry.
/// </summary>
public sealed class AuditSingleLineTests
{
    [Theory]
    [InlineData("a\nAudit Forged by admin", "a Audit Forged by admin")]
    [InlineData("a\r\nb\rc", "a b c")]
    [InlineData("plain", "plain")]
    [InlineData(null, null)]
    public void LineBreaksBecomeSpaces(string? value, string? expected) =>
        Assert.Equal(expected, SerilogAuditLogService.SingleLine(value));
}
