using System.Security.Claims;
using SystemLogowania2.Data;
using SystemLogowania2.Security;
using SystemLogowania2.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDb>(o =>
    o.UseSqlite(builder.Configuration.GetConnectionString("Default") ?? "Data Source=app.db"));
builder.Services.AddScoped<UserService>();

// CSRF: token sprawdzany we wszystkich żądaniach POST
builder.Services.AddControllersWithViews(o => o.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.LoginPath = "/Account/Login";
        o.AccessDeniedPath = "/Account/Denied";
        o.Cookie.Name = "auth";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Lax;
        o.ExpireTimeSpan = TimeSpan.FromHours(12);  // górna granica; właściwy limit to czas bezczynności
        o.SlidingExpiration = false;
        o.Events.OnValidatePrincipal = SessionValidator.ValidateAsync;
    });

builder.Services.AddAuthorization(o =>
{
    // domyślnie każdy adres wymaga zalogowania ([AllowAnonymous] tylko na logowaniu)
    o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
    // jedna polityka na uprawnienie
    foreach (var perm in Permissions.All)
        o.AddPolicy(perm, p => p.RequireAuthenticatedUser()
            .RequireAssertion(ctx => Permissions.Has(ctx.User.FindFirstValue(ClaimTypes.Role), perm)));
});

var app = builder.Build();

// --- inicjalizacja bazy, konto ADMIN, opcjonalnie konta testowe ---
using (var scope = app.Services.CreateScope())
{
    scope.ServiceProvider.GetRequiredService<AppDb>().Database.EnsureCreated();
    var users = scope.ServiceProvider.GetRequiredService<UserService>();
    await users.GetSettingsAsync();

    if (await users.FindByNameAsync("ADMIN") == null)
    {
        var (_, otp) = await users.CreateAsync("ADMIN", Roles.Administrator, builtin: true,
            otp: builder.Configuration["AdminInitialPassword"]);
        Console.WriteLine($"\n*** Utworzono konto ADMIN. Hasło jednorazowe (48 h): {otp}\n");
    }

    if (args.Contains("--seed-test-users"))
    {
        // 7 użytkowników testowych wariantu 6
        var test = new (string Name, string Role)[]
        {
            ("test1", Roles.Administrator), ("test2", Roles.Manager), ("test3", Roles.Manager),
            ("test4", Roles.Editor), ("test5", Roles.Editor), ("test6", Roles.Reader), ("test7", Roles.Reader),
        };
        foreach (var (name, role) in test)
        {
            if (await users.FindByNameAsync(name) != null) { Console.WriteLine($"{name}: już istnieje"); continue; }
            var (_, otp) = await users.CreateAsync(name, role);
            Console.WriteLine($"{name,-7} {role,-14} hasło jednorazowe: {otp}");
        }
        return;
    }
}

app.UseStaticFiles();
app.UseAuthentication();

// Wymuszona zmiana hasła: do czasu zmiany wszystkie adresy prowadzą na /Account/ChangePassword
app.Use(async (ctx, next) =>
{
    if (ctx.Items["user"] is User u && ctx.Items["settings"] is SecuritySettings s
        && UserService.NeedsChange(u, s))
    {
        var path = ctx.Request.Path;
        var allowed = path.StartsWithSegments("/Account/ChangePassword", StringComparison.OrdinalIgnoreCase)
                      || path.StartsWithSegments("/Account/Logout", StringComparison.OrdinalIgnoreCase);
        if (!allowed)
        {
            ctx.Response.Redirect("/Account/ChangePassword");
            return;
        }
    }
    await next();
});

app.UseAuthorization();
app.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");
app.Run();
