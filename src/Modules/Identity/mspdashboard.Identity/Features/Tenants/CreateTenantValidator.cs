using FluentValidation;

namespace mspdashboard.Identity.Features.Tenants;

public sealed class CreateTenantCommandValidator : AbstractValidator<CreateTenantCommand> {
    public CreateTenantCommandValidator() {
        // Lowercase DNS label: letters, digits and inner hyphens, 2-63 characters.
        RuleFor(x => x.Subdomain)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .Length(2, 63)
            .Matches("^[a-z0-9]+(-[a-z0-9]+)*$")
            .WithMessage("'{PropertyName}' must be lowercase letters, digits and single hyphens, and cannot start or end with a hyphen.");

        RuleFor(x => x.CompanyName)
            .NotEmpty()
            .MaximumLength(200);

        RuleFor(x => x.ContactEmail)
            .EmailAddress()
            .MaximumLength(255)
            .When(x => !string.IsNullOrWhiteSpace(x.ContactEmail));

        RuleFor(x => x.ContactPhone)
            .MaximumLength(50);
    }
}
