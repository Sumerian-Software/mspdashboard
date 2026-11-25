using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using mspdashboard.Identity.Features.Tenants;

namespace mspdashboard.Host.Tests.Infrastructure;

public static class TenantRequests {
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static async Task<TenantCreatedResponse> CreateTenantAsync(
        HttpClient client,
        string subdomain,
        string companyName,
        string? contactEmail = null,
        string? contactPhone = null,
        Action<HttpRequestMessage>? configure = null) {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/tenants") {
            Content = JsonContent.Create(
                new CreateTenantCommand(subdomain, companyName, contactEmail, contactPhone),
                options: JsonOptions)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            TestTokens.CreatePlatformAdmin());
        configure?.Invoke(request);

        var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        if (!response.IsSuccessStatusCode) {
            throw new HttpRequestException(
                "POST /api/tenants failed: " + (int)response.StatusCode + " " + body);
        }

        var created = JsonSerializer.Deserialize<TenantCreatedResponse>(body, JsonOptions);
        if (created is null) {
            throw new InvalidOperationException("POST /api/tenants returned an empty body.");
        }

        return created;
    }
}
