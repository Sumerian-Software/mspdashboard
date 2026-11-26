using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;
using mspdashboard.Identity;
using mspdashboard.Identity.Security;
using mspdashboard.Identity.Services;

namespace mspdashboard.Host.Authentication;

public static class DashboardAuthenticationExtensions {
    public const string SmartScheme = "Smart";
    internal const int MinimumSigningKeyLength = 32;

    internal const string RemovedPlaceholderSecret =
        "ChangeThisToASecureKeyInProduction_AtLeast32Characters!";

    public static WebApplicationBuilder AddDashboardSwagger(this WebApplicationBuilder builder) {
        builder.Services.AddSwaggerGen(options => {
            options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme {
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT",
                Description =
                    "JWT from POST /api/auth/token. Paste the access token (Swagger adds the Bearer prefix)."
            });
            options.AddSecurityDefinition("ApiKey", new OpenApiSecurityScheme {
                Type = SecuritySchemeType.ApiKey,
                In = ParameterLocation.Header,
                Name = ApiKeyDefaults.HeaderName,
                Description =
                    "Long-lived API key from POST /api/auth/api-keys (format msp_<prefix>_<secret>)."
            });
            options.AddSecurityRequirement(document => new OpenApiSecurityRequirement {
                [new OpenApiSecuritySchemeReference("Bearer", document)] = []
            });
        });

        return builder;
    }

    public static WebApplicationBuilder AddDashboardAuthentication(this WebApplicationBuilder builder) {
        var configuration = builder.Configuration;
        var issuer = configuration["JwtSettings:Issuer"];
        var audience = configuration["JwtSettings:Audience"];
        var signingKey = ResolveSigningKey(
            builder.Environment.IsDevelopment(),
            configuration["JwtSettings:Secret"]);
        var expirationMinutes = configuration.GetValue(
            "JwtSettings:ExpirationMinutes",
            JwtTokenOptions.DefaultExpirationMinutes);
        if (expirationMinutes <= 0) {
            expirationMinutes = JwtTokenOptions.DefaultExpirationMinutes;
        }

        // Singleton options shared by JwtBearer validation and IJwtAccessTokenIssuer.
        builder.Services.AddSingleton<IOptions<JwtTokenOptions>>(Options.Create(new JwtTokenOptions {
            Issuer = issuer,
            Audience = audience,
            SigningKey = signingKey,
            ExpirationMinutes = expirationMinutes
        }));
        builder.Services.AddSingleton<IJwtAccessTokenIssuer, JwtAccessTokenIssuer>();

        builder.Services.AddAuthentication(options => {
                options.DefaultScheme = SmartScheme;
                options.DefaultAuthenticateScheme = SmartScheme;
                // Challenge via Smart so X-Api-Key / Bearer requests get the matching scheme's
                // 401 (not a cookie redirect). No-header requests still forward to the cookie scheme.
                options.DefaultChallengeScheme = SmartScheme;
                options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
            })
            .AddPolicyScheme(SmartScheme, "Cookie, JWT, or API key", options => {
                options.ForwardDefaultSelector = context => {
                    if (HasApiKeyCredential(context.Request)) {
                        return ApiKeyDefaults.AuthenticationScheme;
                    }

                    var header = context.Request.Headers.Authorization.ToString();
                    if (!string.IsNullOrEmpty(header) &&
                        header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) {
                        return JwtBearerDefaults.AuthenticationScheme;
                    }

                    return IdentityConstants.ApplicationScheme;
                };
            })
            .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(
                ApiKeyDefaults.AuthenticationScheme,
                _ => { })
            .AddJwtBearer(options => {
                options.MapInboundClaims = true;
                var parameters = options.TokenValidationParameters;
                parameters.ValidateLifetime = true;
                parameters.RoleClaimType = ClaimTypes.Role;
                parameters.NameClaimType = ClaimTypes.Name;
                if (!string.IsNullOrWhiteSpace(issuer)) {
                    AddValue(parameters, issuer, audience: false);
                }

                if (!string.IsNullOrWhiteSpace(audience)) {
                    AddValue(parameters, audience, audience: true);
                }

                if (signingKey is not null) {
                    parameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
                    parameters.ValidateIssuerSigningKey = true;
                }
            })
            .AddOpenIdConnect("__oidc_template", options => {
                // Registers OpenIdConnectHandler infrastructure for dynamic per-tenant schemes.
                options.ClientId = "__template__";
                options.Authority = "https://login.microsoftonline.com/common/v2.0";
                options.CallbackPath = "/signin-oidc-template";
                options.SignInScheme = IdentityConstants.ExternalScheme;
            });

        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIdConnectOptions>, OpenIdConnectPostConfigureOptions>());
        builder.Services.AddSingleton<DynamicOidcSchemeManager>();
        builder.Services.AddSingleton<ISsoOidcSchemeInvalidator>(sp =>
            sp.GetRequiredService<DynamicOidcSchemeManager>());

        builder.Services.AddAuthorization(options => {
            options.AddPolicy(AuthorizationPolicies.PlatformAdmin, policy => {
                policy.RequireRole(AuthorizationPolicies.PlatformAdmin);
            });
            options.AddPolicy(AuthorizationPolicies.TenantAdmin, policy => {
                policy.RequireRole(AuthorizationPolicies.TenantAdmin, AuthorizationPolicies.PlatformAdmin);
            });
        });

        return builder;
    }

    internal static string? ResolveSigningKey(bool isDevelopment, string? configuredSecret) {
        var signingKey = Normalize(configuredSecret);
        if (signingKey is not null && signingKey.Length < MinimumSigningKeyLength) {
            throw new InvalidOperationException("JwtSettings:Secret must be at least 32 characters.");
        }

        if (!isDevelopment && signingKey is null) {
            throw new InvalidOperationException(
                "JwtSettings:Secret is required outside Development. " +
                "Set it with dotnet user-secrets or the JwtSettings__Secret environment variable.");
        }

        return signingKey;
    }

    private static string? Normalize(string? configuredSecret) {
        if (string.IsNullOrWhiteSpace(configuredSecret)) {
            return null;
        }

        if (string.Equals(configuredSecret, RemovedPlaceholderSecret, StringComparison.Ordinal)) {
            return null;
        }

        return configuredSecret;
    }

    private static bool HasApiKeyCredential(HttpRequest request) {
        if (request.Headers.TryGetValue(ApiKeyDefaults.HeaderName, out var values) &&
            !string.IsNullOrWhiteSpace(values.ToString())) {
            return true;
        }

        var authorization = request.Headers.Authorization.ToString();
        return !string.IsNullOrEmpty(authorization) &&
               authorization.StartsWith(
                   ApiKeyDefaults.AuthorizationScheme + " ",
                   StringComparison.OrdinalIgnoreCase);
    }

    private static void AddValue(TokenValidationParameters parameters, string value, bool audience) {
        var single = audience ? parameters.ValidAudience : parameters.ValidIssuer;
        var many = audience ? parameters.ValidAudiences : parameters.ValidIssuers;
        var values = new List<string>();
        if (!string.IsNullOrWhiteSpace(single)) {
            values.Add(single);
        }

        if (many is not null) {
            foreach (var existing in many) {
                if (!string.IsNullOrWhiteSpace(existing) && !values.Contains(existing, StringComparer.Ordinal)) {
                    values.Add(existing);
                }
            }
        }

        if (!values.Contains(value, StringComparer.Ordinal)) {
            values.Add(value);
        }

        if (audience) {
            parameters.ValidAudience = null;
            parameters.ValidAudiences = values;
            parameters.ValidateAudience = true;
            return;
        }

        parameters.ValidIssuer = null;
        parameters.ValidIssuers = values;
        parameters.ValidateIssuer = true;
    }
}
