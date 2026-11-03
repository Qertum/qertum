using System.Globalization;
using System.Text;
using Serilog.Core;
using Serilog.Events;

namespace Qertum.ServiceDefaults.Logging;

/// <summary>
/// Escapes control characters (and the Unicode line and paragraph separators) in every string value of a log event,
/// so a value cannot start a new log line. The console template prints string values raw (<c>{Message:lj}</c>), and
/// many logged values are typed by people or come from other systems: a request's common name, an issuer or policy
/// name, a webhook URL, a delivery error. A line feed becomes <c>\n</c>, a carriage return <c>\r</c>, a tab
/// <c>\t</c>, anything else <c>\uXXXX</c>; a value without such characters is left exactly as it was. Structured
/// values are rendered as JSON (<c>:j</c>), which escapes them already, so only top-level strings are rewritten.
/// </summary>
public sealed class ControlCharacterEscapingEnricher : ILogEventEnricher
{
    /// <inheritdoc />
    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        List<LogEventProperty>? replaced = null;
        foreach (var (name, value) in logEvent.Properties)
        {
            if (value is ScalarValue { Value: string text } && NeedsEscaping(text))
                (replaced ??= []).Add(new LogEventProperty(name, new ScalarValue(Escape(text))));
        }
        if (replaced is null) return;
        foreach (var property in replaced) logEvent.AddOrUpdateProperty(property);
    }

    // U+2028 and U+2029 as numbers: the compiler reads either one as a line break even inside a literal.
    private static bool IsUnsafe(char c) => char.IsControl(c) || c is (char)0x2028 or (char)0x2029;

    private static bool NeedsEscaping(string text)
    {
        foreach (var c in text)
            if (IsUnsafe(c)) return true;
        return false;
    }

    /// <summary>The value with each control character or line separator replaced by its escape sequence.</summary>
    public static string Escape(string text)
    {
        var builder = new StringBuilder(text.Length + 8);
        foreach (var c in text)
        {
            switch (c)
            {
                case '\n': builder.Append(@"\n"); break;
                case '\r': builder.Append(@"\r"); break;
                case '\t': builder.Append(@"\t"); break;
                default:
                    if (IsUnsafe(c)) builder.Append(@"\u").Append(((int)c).ToString("X4", CultureInfo.InvariantCulture));
                    else builder.Append(c);
                    break;
            }
        }
        return builder.ToString();
    }
}
