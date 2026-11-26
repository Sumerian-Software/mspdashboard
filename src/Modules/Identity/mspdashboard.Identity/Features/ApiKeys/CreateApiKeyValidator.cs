using FluentValidation;

namespace mspdashboard.Identity.Features.ApiKeys;

public sealed class CreateApiKeyRequestValidator : AbstractValidator<CreateApiKeyRequest> {
    private static readonly TimeSpan MaxLifetime = TimeSpan.FromDays(365 * 2);

    public CreateApiKeyRequestValidator() {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(100);
        RuleFor(x => x.ExpiresAt)
            .Must(BeInTheFuture)
            .WithMessage("Expiration must be in the future.")
            .Must(BeWithinMaxLifetime)
            .WithMessage("Expiration cannot be more than 2 years ahead.");
    }

    private static bool BeInTheFuture(DateTime? expiresAt) {
        var utc = ApiKeyExpiresAt.ToUtc(expiresAt);
        return utc is null || utc.Value > DateTime.UtcNow;
    }

    private static bool BeWithinMaxLifetime(DateTime? expiresAt) {
        var utc = ApiKeyExpiresAt.ToUtc(expiresAt);
        return utc is null || utc.Value <= DateTime.UtcNow.Add(MaxLifetime);
    }
}
