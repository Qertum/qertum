using System.Text.Json;

namespace Qertum.Cli.Auth;

internal static class JwtPayload
{
    public static string ExtractUsername(string accessToken)
    {
        var parts = accessToken.Split('.');
        if (parts.Length != 3) return "unknown";

        try
        {
            var padded = parts[1].PadRight(parts[1].Length + (4 - parts[1].Length % 4) % 4, '=');
            var bytes = Convert.FromBase64String(padded.Replace('-', '+').Replace('_', '/'));
            using var doc = JsonDocument.Parse(bytes);
            var root = doc.RootElement;

            foreach (var claim in new[] { "preferred_username", "name", "sub" })
            {
                if (root.TryGetProperty(claim, out var val) && val.GetString() is { Length: > 0 } s)
                    return s;
            }
        }
        catch
        {
            // fall through
        }

        return "unknown";
    }

    public static IEnumerable<string> ExtractRoles(string accessToken)
    {
        var parts = accessToken.Split('.');
        if (parts.Length != 3) return [];

        var roles = new List<string>();
        try
        {
            var padded = parts[1].PadRight(parts[1].Length + (4 - parts[1].Length % 4) % 4, '=');
            var decoded = Convert.FromBase64String(padded.Replace('-', '+').Replace('_', '/'));
            using var doc = JsonDocument.Parse(decoded);

            if (!doc.RootElement.TryGetProperty("role", out var roleEl)) return roles;

            switch (roleEl.ValueKind)
            {
                case JsonValueKind.Array:
                    foreach (var r in roleEl.EnumerateArray())
                        if (r.GetString() is { } s)
                            roles.Add(s);
                    break;
                case JsonValueKind.String when roleEl.GetString() is { } single:
                    roles.Add(single);
                    break;
            }
        }
        catch
        {
            // fall through
        }

        return roles;
    }

    public static DateTimeOffset? ExtractExpiry(string accessToken)
    {
        var parts = accessToken.Split('.');
        if (parts.Length != 3) return null;

        try
        {
            var padded = parts[1].PadRight(parts[1].Length + (4 - parts[1].Length % 4) % 4, '=');
            var decoded = Convert.FromBase64String(padded.Replace('-', '+').Replace('_', '/'));
            using var doc = JsonDocument.Parse(decoded);

            if (doc.RootElement.TryGetProperty("exp", out var expEl) && expEl.TryGetInt64(out var exp))
                return DateTimeOffset.FromUnixTimeSeconds(exp);
        }
        catch
        {
            // fall through
        }

        return null;
    }
}
