using FluentValidation;

namespace mspdashboard.Identity.Features.Auth;

public sealed class IssueTokenRequestValidator : AbstractValidator<IssueTokenRequest> {
    public IssueTokenRequestValidator() {
        When(HasAnyCredentialField, () => {
            RuleFor(x => x.Email)
                .NotEmpty()
                .MaximumLength(256);
            RuleFor(x => x.Password)
                .NotEmpty();
        });

        RuleFor(x => x.TenantSubdomain)
            .MaximumLength(100);
    }

    private static bool HasAnyCredentialField(IssueTokenRequest request) {
        return !string.IsNullOrWhiteSpace(request.Email) ||
               !string.IsNullOrWhiteSpace(request.Password);
    }
}
