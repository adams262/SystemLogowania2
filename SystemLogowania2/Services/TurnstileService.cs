using System.Text.Json;

namespace SystemLogowania2.Services
{
    public class TurnstileService
    {
        private readonly HttpClient _http;
        private readonly IConfiguration _cfg;
        public TurnstileService(HttpClient http, IConfiguration cfg) { _http = http; _cfg = cfg; }

        public string SiteKey => _cfg["Turnstile:SiteKey"] ?? "";

        public async Task<bool> VerifyAsync(string? token, string? ip)
        {
            if (string.IsNullOrWhiteSpace(token)) return false;     
            var form = new Dictionary<string, string>
            {
                ["secret"] = _cfg["Turnstile:SecretKey"] ?? "",
                ["response"] = token,
            };
            if (!string.IsNullOrEmpty(ip)) form["remoteip"] = ip;
            try
            {
                var resp = await _http.PostAsync(
                    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                    new FormUrlEncodedContent(form));
                using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
                return doc.RootElement.TryGetProperty("success", out var ok) && ok.GetBoolean();
            }
            catch { return false; }    
        }
    }
}
