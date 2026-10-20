namespace Qertum.Cli.Root;

internal interface IPassphrasePrompt
{
    string Read(string prompt);
}

/// <summary>Reads a passphrase from the terminal without echo. Never from an argument or environment variable.</summary>
internal sealed class ConsolePassphrasePrompt : IPassphrasePrompt
{
    public string Read(string prompt)
    {
        Console.Error.Write(prompt);
        var buffer = new System.Text.StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.Backspace) { if (buffer.Length > 0) buffer.Length--; continue; }
            buffer.Append(key.KeyChar);
        }
        Console.Error.WriteLine();
        return buffer.ToString();
    }
}
