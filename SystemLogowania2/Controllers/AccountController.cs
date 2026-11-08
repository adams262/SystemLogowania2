using SystemLogowania2.Models;
using SystemLogowania2.Security;
using SystemLogowania2.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace SystemLogowania2.Controllers;

public class AccountController : AppController
{
    private const string LoginError = "Login lub hasło niepoprawne";
    private static readonly (string Hash, string Salt) Dummy = Passwords.Hash("dummy-password-for-timing");

    private readonly UserService _users;
    private readonly LoginGuard _guard;
    private readonly TurnstileService _turnstile;

    public AccountController(UserService users, LoginGuard guard, TurnstileService turnstile)
    {
        _users = users;
        _guard = guard;
        _turnstile = turnstile;
    }

    [AllowAnonymous]
    [HttpGet]
    public IActionResult Login()
    {
        if (User.Identity?.IsAuthenticated == true) return RedirectToAction("Index", "Home");
        if (Request.Cookies.ContainsKey(SessionValidator.TimeoutCookie))
        {
            Response.Cookies.Delete(SessionValidator.TimeoutCookie);
            ViewBag.Info = "Sesja wygasła z powodu bezczynności. Zaloguj się ponownie.";
        }
        return View(new LoginVm());
    }

    [AllowAnonymous]
    [HttpPost]
    public async Task<IActionResult> Login(LoginVm vm)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "?";
        var settings = await _users.GetSettingsAsync();
        var username = (vm.Username ?? "").Trim();
        var back = new LoginVm { Username = vm.Username };

        // Pułapka na boty: wypełnione ukryte pole = bot (bot nie dostaje informacji o wykryciu)
        if (!string.IsNullOrEmpty(vm.Website))
        {
            await _guard.AlertAsync("BOT-HONEYPOT", ip, $"login='{username}', pole='{vm.Website}'");
            await _guard.AddIpFailureAsync(ip);
            ModelState.AddModelError("", LoginError);
            return View(back);
        }

        // Zadanie dodatkowe: limit prób z jednego IP, niezależnie od loginu
        if (await _guard.IpFailuresAsync(ip) >= settings.IpMaxAttempts)
        {
            Response.StatusCode = 429;
            ModelState.AddModelError("", $"Zbyt wiele nieudanych prób z tego adresu IP. Spróbuj za {LoginGuard.LockMinutes} min.");
            return View(back);
        }

        // CAPTCHA przy logowaniu
        if (!await _turnstile.VerifyAsync(Request.Form["cf-turnstile-response"].ToString(), ip))
        {
            ModelState.AddModelError("", "Weryfikacja CAPTCHA nie powiodła się. Spróbuj ponownie.");
            return View(back);
        }

        var user = await _users.FindByNameAsync(username);
        var password = vm.Password ?? "";

        // Canary token: konto-pułapka
        if (user != null && user.IsCanary)
        {
            await _guard.AlertAsync("CANARY-ACCOUNT", ip, $"próba logowania na konto-pułapkę '{user.Username}'");
            await _guard.AddIpFailureAsync(ip);
            ModelState.AddModelError("", LoginError);
            return View(back);
        }

        // Konto zablokowane po błędnych próbach: pokazujemy pozostały czas
        if (user != null && LoginGuard.RemainingLock(user) is TimeSpan left)
        {
            ModelState.AddModelError("", $"Konto zablokowane. Pozostały czas blokady: {(int)left.TotalMinutes} min {left.Seconds} s.");
            return View(back);
        }

        bool ok;
        if (user != null)
            ok = Passwords.Verify(password, user.PasswordHash, user.Salt);
        else
        {
            Passwords.Verify(password, Dummy.Hash, Dummy.Salt);
            ok = false;
        }

        if (ok && !user!.IsBlocked && !UserService.OtpExpired(user))
        {
            await _guard.RegisterSuccessAsync(user);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(SessionValidator.CreateIdentity(user)));
            return RedirectToAction("Index", "Home");
        }

        // Błędne logowanie: licznik na adresie IP i na koncie
        await _guard.AddIpFailureAsync(ip);
        if (user != null)
        {
            await _guard.RegisterFailureAsync(user, settings.MaxFailedAttempts);
            if (LoginGuard.RemainingLock(user) is TimeSpan l2)
            {
                ModelState.AddModelError("", $"Konto zablokowane na {LoginGuard.LockMinutes} min. Pozostało: {(int)l2.TotalMinutes} min {l2.Seconds} s.");
                return View(back);
            }
        }

        ModelState.AddModelError("", LoginError);
        return View(back);
    }

    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Login");
    }

    [HttpGet]
    public async Task<IActionResult> ChangePassword() => View(await BuildVm(new ChangePasswordVm()));

    [HttpPost]
    public async Task<IActionResult> ChangePassword(ChangePasswordVm vm)
    {

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        if (!await _turnstile.VerifyAsync(Request.Form["cf-turnstile-response"].ToString(), ip))
        {
            ModelState.AddModelError("", "Weryfikacja CAPTCHA nie powiodła się. Spróbuj ponownie.");
            return View(await BuildVm(new ChangePasswordVm()));
        }

        var me = Me!;
        var settings = await _users.GetSettingsAsync();
        var errors = new List<string>();

        if (!Passwords.Verify(vm.OldPassword ?? "", me.PasswordHash, me.Salt))
            errors.Add("Stare hasło jest niepoprawne.");
        else if (vm.NewPassword != vm.NewPassword2)
            errors.Add("Nowe hasła nie są identyczne.");
        else
        {
            errors.AddRange(Passwords.Validate(vm.NewPassword ?? "", settings.PassphraseRule));
            if (errors.Count == 0 && await _users.IsReusedAsync(me, vm.NewPassword!))
                errors.Add("Nowe hasło musi różnić się od poprzednich haseł.");
        }

        if (errors.Count > 0)
        {
            foreach (var e in errors) ModelState.AddModelError("", e);
            return View(await BuildVm(new ChangePasswordVm()));
        }

        await _users.SetNewPasswordAsync(me, vm.NewPassword!);
        TempData["ok"] = "Hasło zostało zmienione.";
        return RedirectToAction("Index", "Home");
    }

    [HttpGet]
    public IActionResult Denied()
    {
        Response.StatusCode = 403;
        return View();
    }

    private async Task<ChangePasswordVm> BuildVm(ChangePasswordVm vm)
    {
        var settings = await _users.GetSettingsAsync();
        vm.Forced = UserService.NeedsChange(Me!, settings);
        vm.Rule = settings.PassphraseRule;
        return vm;
    }
}