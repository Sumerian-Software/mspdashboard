using Microsoft.JSInterop;

namespace mspdashboard.Client.Auth;

public sealed class TenantHeaderHandler : DelegatingHandler {
    private readonly IJSRuntime _js;

    public TenantHeaderHandler(IJSRuntime js) {
        _js = js;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken) {
        try {
            var subdomain = await _js.InvokeAsync<string?>("sessionStorage.getItem", "tenant_subdomain");
            if (!string.IsNullOrWhiteSpace(subdomain) &&
                !request.Headers.Contains("X-Tenant-Subdomain")) {
                request.Headers.Add("X-Tenant-Subdomain", subdomain);
            }
        } catch (InvalidOperationException) {
            // JS interop unavailable during static render / prerender.
        }

        return await base.SendAsync(request, cancellationToken);
    }
}
