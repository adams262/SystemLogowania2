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
    public AccountController(UserService users) => _users = users;

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
        var user = await _users.FindByNameAsync((vm.Username ?? "").Trim());
        var password = vm.Password ?? "";
        bool ok;
        if (user != null)
            ok = Passwords.Verify(password, user.PasswordHash, user.Salt);
        else
        {
            Passwords.Verify(password, Dummy.Hash, Dummy.Salt); // wyrównanie czasu odpowiedzi
            ok = false;
        }

        if (ok && !user!.IsBlocked && !UserService.OtpExpired(user))
        {
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(SessionValidator.CreateIdentity(user)));
            return RedirectToAction("Index", "Home");
        }

        // ten sam komunikat dla złego loginu, hasła, konta zablokowanego i wygasłego hasła jednorazowego
        ModelState.AddModelError("", LoginError);
        return View(new LoginVm { Username = vm.Username });
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
