using FluentValidation;

namespace mspdashboard.Identity.Features.Setup;

public sealed class CompleteSetupRequestValidator : AbstractValidator<CompleteSetupRequest> {
    public CompleteSetupRequestValidator() {
        RuleFor(x => x.CompanyName)
            .Cascade(CascadeMode.Stop)
            .NotEmpty().WithMessage("Organization name is required.")
            .Must(name => name!.Trim().Length <= 200)
            .WithMessage("Organization name must be 200 characters or fewer.");

        RuleFor(x => x.Email)
            .Cascade(CascadeMode.Stop)
            .NotEmpty().WithMessage("Email is required.")
            .Must(HaveDomain).WithMessage("Email must include a domain.");

        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("Password is required.");
    }

    /// <summary>The email, once trimmed, must be local@domain with a usable domain.</summary>
    internal static bool HaveDomain(string? email) {
        var value = email?.Trim() ?? string.Empty;
        var at = value.LastIndexOf('@');
        if (at <= 0 || at == value.Length - 1) {
            return false;
        }

        var domain = value[(at + 1)..].Trim();
        return domain.Length is > 0 and <= 255 && !domain.Contains(' ') && !domain.Contains('@');
    }
}
