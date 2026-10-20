using System.Text.Json;
using FluentValidation;
using Qertum.Services.Webhooks;

namespace Qertum.Services.Validators;

internal sealed class SaveWebhookRequestValidator : AbstractValidator<SaveWebhookRequest>
{
    public SaveWebhookRequestValidator()
    {
        RuleFor(r => r.Name).NotEmpty().MaximumLength(200);

        RuleFor(r => r.Family).IsInEnum();

        RuleFor(r => r.Url)
            .NotEmpty()
            .MaximumLength(2000)
            .Must(url => WebhookDestinationTarget.TryParse(url, out _, out _))
            .WithMessage("Url must be an absolute http or https URL without credentials, fragments, or placeholders in its authority.");

        // Placeholders are checked against the chosen family, so switching a webhook's family
        // re-validates its URL instead of silently emitting blanks.
        RuleFor(r => r.Url)
            .Must((request, url) => WebhookUrlTemplate.TryValidate(url, request.Family, out _))
            .WithMessage((request, url) =>
            {
                WebhookUrlTemplate.TryValidate(url, request.Family, out var error);
                return error ?? "Url contains an unsupported placeholder.";
            })
            .When(r => Enum.IsDefined(r.Family));

        RuleFor(r => r.EventsJson)
            .NotEmpty()
            .Must((request, json) => BeEventsOfFamily(json, request.Family))
            .WithMessage((request, json) =>
            {
                var allowed = string.Join(", ",
                    WellKnownWebhookEvents.EventsFor(request.Family).OrderBy(e => e, StringComparer.Ordinal));

                // Name the offending events, not only the valid ones: an operator who mistyped one
                // event in a list of six should not have to diff the two sets by eye.
                var strays = StrayEvents(json, request.Family);
                var lead = strays.Count > 0
                    ? $"EventsJson names event(s) outside the {request.Family} family: {string.Join(", ", strays)}. "
                    : $"EventsJson must be a JSON array of {request.Family} event names. ";

                return lead + $"Valid {request.Family} events: {allowed}. An empty array subscribes to the whole family.";
            })
            .When(r => Enum.IsDefined(r.Family));
    }

    private static bool BeEventsOfFamily(string json, WebhookEventFamily family)
    {
        try
        {
            var events = JsonSerializer.Deserialize<string[]>(json);
            if (events is null) return false;

            var allowed = WellKnownWebhookEvents.EventsFor(family);
            return events.All(e => allowed.Contains(e));
        }
        catch
        {
            return false;
        }
    }

    /// <summary>The event names in <paramref name="json"/> that the family does not own; empty when it is unparseable.</summary>
    private static List<string> StrayEvents(string json, WebhookEventFamily family)
    {
        try
        {
            var events = JsonSerializer.Deserialize<string[]>(json);
            if (events is null) return [];

            var allowed = WellKnownWebhookEvents.EventsFor(family);
            return [.. events.Where(e => !allowed.Contains(e))];
        }
        catch
        {
            return [];
        }
    }
}
