using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;

namespace mspdashboard.Client.Auth;

public sealed class PortalAuthStateProvider : AuthenticationStateProvider {
    private readonly HttpClient _http;
    private readonly ClaimsPrincipal _anonymous = new(new ClaimsIdentity());

    public PortalAuthStateProvider(HttpClient http) {
        _http = http;
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync() {
        try {
            var user = await _http.GetFromJsonAsync<AuthUserDto>("api/auth/me");
            if (user is null || string.IsNullOrWhiteSpace(user.Email)) {
                return new AuthenticationState(_anonymous);
            }

            return new AuthenticationState(CreatePrincipal(user));
        } catch {
            return new AuthenticationState(_anonymous);
        }
    }

    public void NotifyLoggedIn(AuthUserDto user) {
        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(CreatePrincipal(user))));
    }

    public void NotifyLoggedOut() {
        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(_anonymous)));
    }

    private static ClaimsPrincipal CreatePrincipal(AuthUserDto user) {
        var claims = new List<Claim> {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Email, user.Email),
            new(ClaimTypes.Name, user.Email),
            new("tenant_id", user.TenantId.ToString())
        };
        if (!string.IsNullOrWhiteSpace(user.TenantSubdomain)) {
            claims.Add(new Claim("tenant_subdomain", user.TenantSubdomain));
        }

        foreach (var role in user.Roles) {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        return new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType: "mspdashboard"));
    }
}

public sealed class AuthUserDto {
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public Guid TenantId { get; set; }
    public string? TenantSubdomain { get; set; }
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public List<string> Roles { get; set; } = new();
}
