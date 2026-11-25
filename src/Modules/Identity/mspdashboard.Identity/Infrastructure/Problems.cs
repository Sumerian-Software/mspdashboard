using Microsoft.AspNetCore.Mvc;

namespace mspdashboard.Identity.Infrastructure;

/// <summary>
/// Builds ProblemDetails responses for endpoint-level (database or service dependent) checks.
/// Wolverine writes the returned instance as application/problem+json.
/// </summary>
public static class Problems {
    public static ProblemDetails Conflict(string detail) {
        return new ProblemDetails {
            Status = StatusCodes.Status409Conflict,
            Title = "Conflict",
            Detail = detail
        };
    }

    public static ProblemDetails NotFound(string detail) {
        return new ProblemDetails {
            Status = StatusCodes.Status404NotFound,
            Title = "Not found",
            Detail = detail
        };
    }

    public static ProblemDetails BadRequest(string detail) {
        return new ProblemDetails {
            Status = StatusCodes.Status400BadRequest,
            Title = "Bad request",
            Detail = detail
        };
    }

    /// <summary>
    /// Same shape FluentValidation failures use: a 400 with an "errors" map keyed by field name.
    /// </summary>
    public static ProblemDetails Validation(string field, params string[] messages) {
        var problem = new ProblemDetails {
            Status = StatusCodes.Status400BadRequest,
            Title = "One or more validation errors occurred."
        };
        problem.Extensions["errors"] = new Dictionary<string, string[]> { [field] = messages };
        return problem;
    }
}
