using Qertum.Services;

namespace Qertum.Web.Components.Shared;

/// <summary>
/// Error text for a failed API call. Appends the server's correlation id so an operator can quote it and
/// find the entry in the console log, as <c>qca</c> prints it after its error line.
/// </summary>
public static class ProblemText
{
    /// <summary>
    /// <paramref name="message"/> followed by <c>(correlation id: …)</c> when <paramref name="exception"/> is an
    /// <see cref="ApiProblemException"/> whose response carried one; otherwise <paramref name="message"/> unchanged.
    /// </summary>
    public static string WithCorrelationId(this Exception exception, string message)
    {
        // A two-person approval refusal says where to ask; the page cannot link from plain text, so it names the page.
        if (exception is ApiProblemException { Approval: not null })
            message += " Ask for an approval on the Approvals page.";
        return exception is ApiProblemException { CorrelationId: { Length: > 0 } id }
            ? $"{message} (correlation id: {id})"
            : message;
    }
}
