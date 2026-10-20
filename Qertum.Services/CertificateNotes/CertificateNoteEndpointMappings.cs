using FluentValidation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Qertum.Services.Auth;

namespace Qertum.Services.CertificateNotes;

/// <summary>REST surface of certificate notes under <c>/v1/certificate-requests/{id}/notes</c>.</summary>
public static class CertificateNoteEndpointMappings
{
    /// <summary>
    /// Maps add, edit and delete (all <c>certificates.view</c>). Notes are read through the timeline. Existence (404)
    /// and authorship (403) are decided before the body is validated, so a stranger learns nothing about a note.
    /// </summary>
    /// <param name="v1">The <c>/v1</c> group.</param>
    /// <returns>The same group.</returns>
    public static RouteGroupBuilder MapCertificateNoteApi(this RouteGroupBuilder v1)
    {
        var group = v1.MapGroup("/certificate-requests/{id:guid}/notes").WithTags("CertificateNotes")
            .RequireAuthorization(AppPermissions.CertificatesView).RequireRateLimiting("api");

        group.MapPost("/", async (Guid id, SaveCertificateNoteRequest body, IValidator<SaveCertificateNoteRequest> validator,
            ICertificateNoteService notes, HttpContext http, IIdentityClaimsMapper claims, CancellationToken ct) =>
        {
            // Authorship is bound to the immutable subject; a token without one cannot own a note.
            var subject = claims.GetSubject(http.User);
            if (string.IsNullOrWhiteSpace(subject)) return Results.Forbid();

            // Existence first: an unknown request is a 404 whatever the body says.
            if (!await notes.RequestExistsAsync(new CertificateRequestId(id), ct)) return ApiProblem.NotFound();

            var validation = await validator.ValidateAsync(body, ct);
            if (!validation.IsValid)
                return Results.ValidationProblem(validation.ToErrorDictionary());

            var result = await notes.AddAsync(new CertificateRequestId(id), body.Body, subject, claims.GetName(http.User), ct);
            return result.Outcome switch
            {
                NoteOutcome.Done => Results.Created($"/v1/certificate-requests/{id}/notes/{result.Note!.Id}", result.Note),
                NoteOutcome.TooMany => ApiProblem.Conflict($"A request holds at most {CertificateNote.MaxPerRequest} notes."),
                _ => ApiProblem.NotFound()
            };
        });

        group.MapPut("/{noteId:guid}", async (Guid id, Guid noteId, SaveCertificateNoteRequest body, IValidator<SaveCertificateNoteRequest> validator,
            ICertificateNoteService notes, HttpContext http, IIdentityClaimsMapper claims, CancellationToken ct) =>
        {
            var subject = claims.GetSubject(http.User);
            if (string.IsNullOrWhiteSpace(subject)) return Results.Forbid();

            // Authorship is checked before the body: a stranger gets 403 whatever they send.
            switch (await notes.CheckAuthorAsync(new CertificateRequestId(id), new NoteId(noteId), subject, ct))
            {
                case NoteOutcome.NoteNotFound or NoteOutcome.RequestNotFound: return ApiProblem.NotFound();
                case NoteOutcome.NotAuthor: return Results.Forbid();
            }

            var validation = await validator.ValidateAsync(body, ct);
            if (!validation.IsValid)
                return Results.ValidationProblem(validation.ToErrorDictionary());

            var result = await notes.EditAsync(new CertificateRequestId(id), new NoteId(noteId), body.Body, subject, claims.GetName(http.User), ct);
            return result.Outcome switch
            {
                NoteOutcome.Done => Results.Ok(result.Note),
                NoteOutcome.NotAuthor => Results.Forbid(),
                _ => ApiProblem.NotFound()
            };
        });

        group.MapDelete("/{noteId:guid}", async (Guid id, Guid noteId, ICertificateNoteService notes, HttpContext http,
            IIdentityClaimsMapper claims, CancellationToken ct) =>
        {
            var subject = claims.GetSubject(http.User);
            if (string.IsNullOrWhiteSpace(subject)) return Results.Forbid();

            var result = await notes.DeleteAsync(new CertificateRequestId(id), new NoteId(noteId), subject, claims.GetName(http.User), ct);
            return result.Outcome switch
            {
                NoteOutcome.Done => Results.NoContent(),
                NoteOutcome.NotAuthor => Results.Forbid(),
                _ => ApiProblem.NotFound()
            };
        });

        return v1;
    }
}
