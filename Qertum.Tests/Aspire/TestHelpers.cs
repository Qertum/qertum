using System.Text.Json;

namespace Qertum.Tests.Aspire;

public static class TestHelpers
{
    public static string UniqueCN() => $"test-{Guid.NewGuid():N}.local";

    public static async Task<T> PollUntilAsync<T>(
        Func<Task<T>> fetch,
        Func<T, bool> predicate,
        TimeSpan? timeout = null,
        TimeSpan? interval = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(30));
        var delay = interval ?? TimeSpan.FromMilliseconds(500);
        while (true)
        {
            var result = await fetch();
            if (predicate(result))
                return result;
            if (DateTime.UtcNow >= deadline)
                throw new TimeoutException($"Condition not met within {timeout ?? TimeSpan.FromSeconds(30)}.");
            await Task.Delay(delay, TestContext.Current.CancellationToken);
        }
    }

    public static JsonElement DecodeJwtPayload(string token)
    {
        var parts = token.Split('.');
        if (parts.Length < 2)
            throw new ArgumentException("Not a valid JWT.", nameof(token));
        var payload = parts[1].Replace('-', '+').Replace('_', '/');
        payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
        var bytes = Convert.FromBase64String(payload);
        return JsonDocument.Parse(bytes).RootElement;
    }
}
