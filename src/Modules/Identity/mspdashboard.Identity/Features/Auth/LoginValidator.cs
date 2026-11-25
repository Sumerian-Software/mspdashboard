using FluentValidation;

namespace mspdashboard.Identity.Features.Auth;

public sealed class LoginRequestValidator : AbstractValidator<LoginRequest> {
    public LoginRequestValidator() {
        RuleFor(x => x.Email)
            .NotEmpty()
            .MaximumLength(256);

        RuleFor(x => x.Password)
            .NotEmpty();

        RuleFor(x => x.TenantSubdomain)
            .MaximumLength(100);
    }
}
