using System.Net.Http.Json;
using mspdashboard.Shared;

namespace mspdashboard.Client.Auth;

public sealed class AuthApiClient {
    private readonly HttpClient _http;

    public AuthApiClient(HttpClient http) {
        _http = http;
    }

    public async Task<ResolveTenantDto?> ResolveTenantAsync(string? email, string? subdomain) {
        var response = await _http.PostAsJsonAsync("api/auth/resolve-tenant", new {
            email,
            subdomain
        });
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound) {
            return null;
        }

        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<ResolveTenantDto>();
    }

    public async Task<(AuthUserDto? User, string? Error, bool LockedOut)> LoginAsync(
        string email, string password, string? tenantSubdomain) {
        var response = await _http.PostAsJsonAsync("api/auth/login", new {
            email,
            password,
            tenantSubdomain
        });

        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized) {
            return (null, "Invalid email or password.", false);
        }

        if ((int)response.StatusCode == 423) {
            return (null, "Account locked. Try again later.", true);
        }

        if (!response.IsSuccessStatusCode) {
            var body = await response.Content.ReadAsStringAsync();
            return (null, string.IsNullOrWhiteSpace(body) ? "Login failed." : body, false);
        }

        var payload = await response.Content.ReadFromJsonAsync<LoginResponseDto>();
        return (payload?.User, null, false);
    }

    public async Task LogoutAsync() {
        await _http.PostAsync("api/auth/logout", null);
    }

    public string SsoChallengeUrl(Guid providerId, string returnUrl = "/") {
        return $"api/auth/sso/{providerId:D}/challenge?returnUrl={Uri.EscapeDataString(returnUrl)}";
    }

    public async Task<SetupStatusDto?> GetSetupStatusAsync() {
        var response = await _http.GetAsync("api/setup/status");
        if (!response.IsSuccessStatusCode) {
            return null;
        }

        return await response.Content.ReadFromJsonAsync<SetupStatusDto>();
    }

    public async Task<(AuthUserDto? User, string? Error)> CompleteSetupAsync(
        string companyName, string email, string password) {
        var response = await _http.PostAsJsonAsync("api/setup", new {
            companyName,
            email,
            password
        });

        if (response.IsSuccessStatusCode) {
            var payload = await response.Content.ReadFromJsonAsync<LoginResponseDto>();
            return (payload?.User, null);
        }

        return (null, await ReadErrorAsync(response) ?? "Setup failed.");
    }

    private static async Task<string?> ReadErrorAsync(HttpResponseMessage response) {
        try {
            var body = await response.Content.ReadFromJsonAsync<ApiErrorDto>();
            return string.IsNullOrWhiteSpace(body?.Error) ? null : body.Error;
        } catch (Exception) {
            return null;
        }
    }
}

public sealed class ResolveTenantDto {
    public Guid TenantId { get; set; }
    public string Subdomain { get; set; } = string.Empty;
    public string CompanyName { get; set; } = string.Empty;
    public List<SsoProviderPublicDto> SsoProviders { get; set; } = new();
}

public sealed class SsoProviderPublicDto {
    public Guid Id { get; set; }
    public string DisplayName { get; set; } = string.Empty;
    public SsoProviderType ProviderType { get; set; }
}

public sealed class LoginResponseDto {
    public AuthUserDto User { get; set; } = new();
}

public sealed class SetupStatusDto {
    public bool SetupRequired { get; set; }
}

public sealed class ApiErrorDto {
    public string? Error { get; set; }
}
