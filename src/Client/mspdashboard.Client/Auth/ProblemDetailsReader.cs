using System.Text.Json;

namespace mspdashboard.Client.Auth;

/// <summary>
/// Turns an API failure response (ProblemDetails or plain text) into one message for the UI.
/// Prefers the per-field validation messages, then detail, then title.
/// </summary>
public static class ProblemDetailsReader {
    public static async Task<string> ReadMessageAsync(HttpResponseMessage response, string fallback) {
        try {
            var body = await response.Content.ReadAsStringAsync();
            if (string.IsNullOrWhiteSpace(body)) {
                return fallback;
            }

            if (!body.TrimStart().StartsWith('{')) {
                return body;
            }

            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            if (root.TryGetProperty("errors", out var errors) && errors.ValueKind == JsonValueKind.Object) {
                var messages = errors.EnumerateObject()
                    .Where(p => p.Value.ValueKind == JsonValueKind.Array)
                    .SelectMany(p => p.Value.EnumerateArray())
                    .Where(m => m.ValueKind == JsonValueKind.String)
                    .Select(m => m.GetString())
                    .Where(m => !string.IsNullOrWhiteSpace(m))
                    .Distinct()
                    .ToList();
                if (messages.Count > 0) {
                    return string.Join(" ", messages);
                }
            }

            foreach (var name in new[] { "detail", "title" }) {
                if (root.TryGetProperty(name, out var value) &&
                    value.ValueKind == JsonValueKind.String &&
                    !string.IsNullOrWhiteSpace(value.GetString())) {
                    return value.GetString()!;
                }
            }

            return fallback;
        } catch (JsonException) {
            return fallback;
        }
    }
}
