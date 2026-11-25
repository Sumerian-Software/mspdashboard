using FluentValidation;
using mspdashboard.Shared;

namespace mspdashboard.Identity.Features.Sso;

public sealed class CreateSsoProviderRequestValidator : AbstractValidator<CreateSsoProviderRequest> {
    public CreateSsoProviderRequestValidator() {
        RuleFor(x => x.ProviderType).IsInEnum();
        RuleFor(x => x.DisplayName).NotEmpty().MaximumLength(200);
        RuleFor(x => x.Authority).MustBeHttpUrl();
        RuleFor(x => x.ClientId).NotEmpty().MaximumLength(200);
        RuleFor(x => x.ClientSecret).NotEmpty().MaximumLength(1000);
        RuleFor(x => x.Scopes).MaximumLength(500);
    }
}

public sealed class UpdateSsoProviderRequestValidator : AbstractValidator<UpdateSsoProviderRequest> {
    public UpdateSsoProviderRequestValidator() {
        RuleFor(x => x.ProviderType).IsInEnum();
        RuleFor(x => x.DisplayName).NotEmpty().MaximumLength(200);
        RuleFor(x => x.Authority).MustBeHttpUrl();
        RuleFor(x => x.ClientId).NotEmpty().MaximumLength(200);
        // A blank secret on update means "keep the stored secret".
        RuleFor(x => x.ClientSecret).MaximumLength(1000);
        RuleFor(x => x.Scopes).MaximumLength(500);
    }
}

internal static class SsoValidationRules {
    public static IRuleBuilderOptions<T, string> MustBeHttpUrl<T>(this IRuleBuilder<T, string> rule) {
        return rule
            .NotEmpty()
            .MaximumLength(500)
            // Blank values are reported by NotEmpty above.
            .Must(value => string.IsNullOrWhiteSpace(value)
                           || Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri)
                           && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp))
            .WithMessage("'{PropertyName}' must be an absolute http or https URL.");
    }
}
