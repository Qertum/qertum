using Microsoft.AspNetCore.Http;

namespace Qertum.Services;

/// <summary>
/// The one way a REST handler answers an error: RFC 9457 problem details, so every error has the same
/// shape (<c>type</c>, <c>title</c>, <c>status</c>, <c>detail</c>) and <c>Qertum.ApiClient</c>'s
/// <c>ApiProblemException</c> can read any of them. <c>ProblemDetailsTests</c> fails if a REST mapping
/// answers an error as a bare string, an anonymous object or an empty body. ACME and EST answer in
/// their protocols' formats and do not use this.
/// </summary>
public static class ApiProblem
{
    public static IResult NotFound(string detail = "The requested resource does not exist.") =>
        Results.Problem(detail: detail, statusCode: StatusCodes.Status404NotFound, title: "Not Found");

    public static IResult BadRequest(string detail) =>
        Results.Problem(detail: detail, statusCode: StatusCodes.Status400BadRequest, title: "Bad Request");

    public static IResult Conflict(string detail) =>
        Results.Problem(detail: detail, statusCode: StatusCodes.Status409Conflict, title: "Conflict");
}
