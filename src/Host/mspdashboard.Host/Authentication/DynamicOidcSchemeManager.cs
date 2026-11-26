using System.Collections.Concurrent;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using mspdashboard.Core.Data;
using mspdashboard.Identity.Security;
using mspdashboard.Identity.Services;

namespace mspdashboard.Host.Authentication;

public sealed class DynamicOidcSchemeManager : ISsoOidcSchemeInvalidator {
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IOptionsMonitorCache<OpenIdConnectOptions> _optionsCache;
    private readonly IEnumerable<IPostConfigureOptions<OpenIdConnectOptions>> _postConfigures;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ConcurrentDictionary<string, byte> _registered = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _gate = new(1, 1);

    public DynamicOidcSchemeManager(
        IAuthenticationSchemeProvider schemeProvider,
        IOptionsMonitorCache<OpenIdConnectOptions> optionsCache,
        IEnumerable<IPostConfigureOptions<OpenIdConnectOptions>> postConfigures,
        IServiceScopeFactory scopeFactory) {
        _schemeProvider = schemeProvider;
        _optionsCache = optionsCache;
        _postConfigures = postConfigures;
        _scopeFactory = scopeFactory;
    }

    /// <summary>
    /// Registers (or confirms) the OIDC scheme for an enabled provider.
    /// Returns false when the provider is missing or disabled.
    /// </summary>
    public async Task<bool> EnsureSchemeAsync(Guid providerId, CancellationToken cancellationToken = default) {
        var scheme = SsoSchemeNames.ForProvider(providerId);
        if (_registered.ContainsKey(scheme) && await _schemeProvider.GetSchemeAsync(scheme) is not null) {
            return true;
        }

        await _gate.WaitAsync(cancellationToken);
        try {
            if (_registered.ContainsKey(scheme) && await _schemeProvider.GetSchemeAsync(scheme) is not null) {
                return true;
            }

            await using var scope = _scopeFactory.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var protector = scope.ServiceProvider.GetRequiredService<SsoSecretProtector>();

            var provider = await db.TenantSsoProviders.AsNoTracking()
                .IgnoreQueryFilters()
                .FirstOrDefaultAsync(p => p.Id == providerId && p.IsEnabled, cancellationToken);
            if (provider is null) {
                return false;
            }

            var clientSecret = protector.Unprotect(provider.ClientSecretProtected);
            var options = new OpenIdConnectOptions {
                Authority = provider.Authority,
                ClientId = provider.ClientId,
                ClientSecret = clientSecret,
                ResponseType = "code",
                SaveTokens = false,
                GetClaimsFromUserInfoEndpoint = true,
                CallbackPath = $"/api/auth/sso/callback/{provider.Id:N}",
                SignInScheme = IdentityConstants.ExternalScheme,
                MapInboundClaims = true
            };

            foreach (var scopeName in provider.Scopes.Split(
                         ' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)) {
                if (!options.Scope.Contains(scopeName)) {
                    options.Scope.Add(scopeName);
                }
            }

            foreach (var postConfigure in _postConfigures) {
                postConfigure.PostConfigure(scheme, options);
            }

            _optionsCache.TryRemove(scheme);
            _optionsCache.TryAdd(scheme, options);

            if (await _schemeProvider.GetSchemeAsync(scheme) is null) {
                _schemeProvider.AddScheme(
                    new AuthenticationScheme(scheme, provider.DisplayName, typeof(OpenIdConnectHandler)));
            }

            _registered[scheme] = 0;
            return true;
        } finally {
            _gate.Release();
        }
    }

    public void Invalidate(Guid providerId) {
        // Remove the scheme as well as cached options. Leaving a registered
        // OpenIdConnectHandler without options causes the auth middleware to rebuild
        // empty defaults and can fail every request that probes IAuthenticationRequestHandler.
        _gate.Wait();
        try {
            var scheme = SsoSchemeNames.ForProvider(providerId);
            _optionsCache.TryRemove(scheme);
            _schemeProvider.RemoveScheme(scheme);
            _registered.TryRemove(scheme, out _);
        } finally {
            _gate.Release();
        }
    }
}
