using FluentValidation;
using mspdashboard.Shared;

namespace mspdashboard.Identity.Features.Sso;

public sealed class CreateSsoProviderRequestValidator : AbstractValidator<CreateSsoProviderRequest> {
    public CreateSsoProviderRequestValidator() {
        RuleFor(x => x.ProviderType).IsInEnum();
        RuleFor(x => x.DisplayName).NotEmpty().MaximumLength(200);
        RuleFor(x => x.Authority).MustBeAuthorityFor(x => x.ProviderType);
        RuleFor(x => x.ClientId).NotEmpty().MaximumLength(200);
        RuleFor(x => x.ClientSecret).NotEmpty().MaximumLength(1000);
        RuleFor(x => x.Scopes).MaximumLength(500);
    }
}

public sealed class UpdateSsoProviderRequestValidator : AbstractValidator<UpdateSsoProviderRequest> {
    public UpdateSsoProviderRequestValidator() {
        RuleFor(x => x.ProviderType).IsInEnum();
        RuleFor(x => x.DisplayName).NotEmpty().MaximumLength(200);
        RuleFor(x => x.Authority).MustBeAuthorityFor(x => x.ProviderType);
        RuleFor(x => x.ClientId).NotEmpty().MaximumLength(200);
        // A blank secret on update means "keep the stored secret".
        RuleFor(x => x.ClientSecret).MaximumLength(1000);
        RuleFor(x => x.Scopes).MaximumLength(500);
    }
}

internal static class SsoValidationRules {
    public static IRuleBuilderOptions<T, string> MustBeAuthorityFor<T>(
        this IRuleBuilder<T, string> rule,
        Func<T, SsoProviderType> providerType) {
        return rule
            .NotEmpty()
            .MaximumLength(500)
            // Blank values are reported by NotEmpty above.
            .Must((instance, authority) => string.IsNullOrWhiteSpace(authority)
                                           || IsValidAuthority(providerType(instance), authority))
            .WithMessage("'{PropertyName}' is not valid for the selected provider type.");
    }

    internal static bool IsValidAuthority(SsoProviderType providerType, string? authority) {
        if (string.IsNullOrWhiteSpace(authority)) {
            return false;
        }

        var trimmed = authority.Trim();
        return providerType switch {
            SsoProviderType.Google => IsGoogleAuthority(trimmed),
            SsoProviderType.MicrosoftEntra => IsEntraAuthority(trimmed),
            SsoProviderType.GenericOidc => IsAbsoluteHttpUrl(trimmed),
            _ => false
        };
    }

    private static bool IsGoogleAuthority(string authority) {
        var normalized = authority.TrimEnd('/');
        return string.Equals(normalized, "https://accounts.google.com", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsEntraAuthority(string authority) {
        if (!Uri.TryCreate(authority, UriKind.Absolute, out var uri)) {
            return false;
        }

        return uri.Scheme == Uri.UriSchemeHttps
               && string.Equals(uri.Host, "login.microsoftonline.com", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsAbsoluteHttpUrl(string authority) {
        return Uri.TryCreate(authority, UriKind.Absolute, out var uri)
               && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp);
    }
}
