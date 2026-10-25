using System.Security.Claims;
using SystemLogowania2.Data;
using SystemLogowania2.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace SystemLogowania2.Security;

/// <summary>
/// Sprawdzane przy KAŻDYM żądaniu: czy konto istnieje i nie jest zablokowane, czy sesja
/// nie przekroczyła czasu bezczynności (ustawianego przez admina w bazie) oraz odświeżenie
/// roli i znacznika ostatniej aktywności.
/// </summary>
public static class SessionValidator
{
    public const string LastClaim = "last";
    public const string TimeoutCookie = "timeout";

    public static ClaimsIdentity CreateIdentity(User u) => new(new[]
    {
        new Claim(ClaimTypes.NameIdentifier, u.Id.ToString()),
        new Claim(ClaimTypes.Name, u.Username),
        new Claim(ClaimTypes.Role, u.Role),
        new Claim(LastClaim, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
    }, CookieAuthenticationDefaults.AuthenticationScheme);

    public static async Task ValidateAsync(CookieValidatePrincipalContext ctx)
    {
        var users = ctx.HttpContext.RequestServices.GetRequiredService<UserService>();
        var principal = ctx.Principal!;

        User? user = null;
        if (int.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var id))
            user = await users.GetAsync(id);
        var settings = await users.GetSettingsAsync();

        var idle = long.TryParse(principal.FindFirstValue(LastClaim), out var last)
            ? DateTimeOffset.UtcNow.ToUnixTimeSeconds() - last
            : long.MaxValue;
        var timedOut = idle > settings.SessionTimeoutMinutes * 60L;

        if (user == null || user.IsBlocked || timedOut)
        {
            if (timedOut)
                ctx.Response.Cookies.Append(TimeoutCookie, "1",
                    new CookieOptions { MaxAge = TimeSpan.FromMinutes(5), HttpOnly = true });
            ctx.RejectPrincipal();
            await ctx.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return;
        }

        ctx.HttpContext.Items["user"] = user;
        ctx.HttpContext.Items["settings"] = settings;
        ctx.ReplacePrincipal(new ClaimsPrincipal(CreateIdentity(user))); // nowy znacznik "last"
        ctx.ShouldRenew = true;
    }
}
