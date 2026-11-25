using Microsoft.AspNetCore.Http;

namespace mspdashboard.Host.Services;

public interface IExternalLoginService {
    Task<string> CompleteExternalLoginAsync(HttpContext httpContext, string? returnUrl);
}
