using System.Text.RegularExpressions;
using SystemLogowania2.Data;
using SystemLogowania2.Models;
using SystemLogowania2.Security;
using SystemLogowania2.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SystemLogowania2.Controllers;

public class AdminController : AppController
{
    private static readonly Regex UsernameRe = new("^[A-Za-z0-9_.-]{3,32}$");
    private readonly UserService _users;
    public AdminController(UserService users) => _users = users;

    [Authorize(Policy = Permissions.UsersManage)]
    public async Task<IActionResult> Users() => View(await _users.ListAsync());

    [Authorize(Policy = Permissions.UsersManage)]
    [HttpGet]
    public IActionResult New() => View("UserForm", new UserFormVm { Role = Roles.Reader });

    [Authorize(Policy = Permissions.UsersManage)]
    [HttpPost]
    public async Task<IActionResult> New(UserFormVm vm)
    {
        var username = (vm.Username ?? "").Trim();
        if (!UsernameRe.IsMatch(username))
            ModelState.AddModelError("", "Login: 3-32 znaków (litery, cyfry, _ . -).");
        else if (vm.Role == null || !Roles.All.Contains(vm.Role))
            ModelState.AddModelError("", "Niepoprawna rola.");
        else if (await _users.FindByNameAsync(username) != null)
            ModelState.AddModelError("", "Taki login już istnieje.");
        else
        {
            var (_, otp) = await _users.CreateAsync(username, vm.Role);
            return View("OtpResult", new OtpVm { Username = username, Otp = otp, Hours = Passwords.OtpValidHours });
        }
        return View("UserForm", vm);
    }

    [Authorize(Policy = Permissions.UsersManage)]
    [HttpGet]
    public async Task<IActionResult> Edit(int id)
    {
        var user = await _users.GetAsync(id);
        if (user == null) return NotFound();
        return View("UserForm", new UserFormVm { Id = user.Id, Username = user.Username, Role = user.Role });
    }

    [Authorize(Policy = Permissions.UsersManage)]
    [HttpPost]
    public async Task<IActionResult> Edit(int id, UserFormVm vm)
    {
        var user = await _users.GetAsync(id);
        if (user == null) return NotFound();
        var username = (vm.Username ?? "").Trim();
        var other = await _users.FindByNameAsync(username);

        if (user.IsBuiltin)
            ModelState.AddModelError("", "Konta ADMIN nie można edytować.");
        else if (!UsernameRe.IsMatch(username) || vm.Role == null || !Roles.All.Contains(vm.Role))
            ModelState.AddModelError("", "Niepoprawny login lub rola.");
        else if (other != null && other.Id != id)
            ModelState.AddModelError("", "Taki login już istnieje.");
        else
        {
            user.Username = username;
            user.Role = vm.Role;
            await _users.SaveAsync();
            TempData["ok"] = "Zapisano zmiany.";
            return RedirectToAction(nameof(Users));
        }
        vm.Id = id;
        return View("UserForm", vm);
    }

    [Authorize(Policy = Permissions.UsersManage)]
    [HttpPost]
    public async Task<IActionResult> Block(int id)
    {
        var user = await Guard(id);
        if (user != null)
        {
            user.IsBlocked = !user.IsBlocked;
            await _users.SaveAsync();
            TempData["ok"] = user.IsBlocked ? "Konto zablokowane." : "Konto odblokowane.";
        }
        return RedirectToAction(nameof(Users));
    }

    [Authorize(Policy = Permissions.UsersManage)]
    [HttpPost]
    public async Task<IActionResult> Delete(int id)
    {
        var user = await Guard(id);
        if (user != null)
        {
            await _users.DeleteAsync(user);
            TempData["ok"] = "Użytkownik usunięty.";
        }
        return RedirectToAction(nameof(Users));
    }

    [Authorize(Policy = Permissions.UsersManage)]
    [HttpPost]
    public async Task<IActionResult> Reset(int id)
    {
        var user = await Guard(id);
        if (user == null) return RedirectToAction(nameof(Users));
        var otp = await _users.ResetAsync(user);
        return View("OtpResult", new OtpVm { Username = user.Username, Otp = otp, Hours = Passwords.OtpValidHours });
    }

    [Authorize(Policy = Permissions.SettingsManage)]
    [HttpGet]
    public async Task<IActionResult> Settings()
    {
        var s = await _users.GetSettingsAsync();
        return View(new SettingsVm
        {
            PassphraseRule = s.PassphraseRule,
            PasswordValidityDays = s.PasswordValidityDays,
            SessionTimeoutMinutes = s.SessionTimeoutMinutes,
        });
    }

    [Authorize(Policy = Permissions.SettingsManage)]
    [HttpPost]
    public async Task<IActionResult> Settings(SettingsVm vm)
    {
        if (vm.PasswordValidityDays is < 0 or > 3650 || vm.SessionTimeoutMinutes is < 1 or > 1440)
        {
            ModelState.AddModelError("", "Ważność hasła: 0-3650 dni (0 = bezterminowo); czas bezczynności: 1-1440 minut.");
            return View(vm);
        }
        var s = await _users.GetSettingsAsync();
        s.PassphraseRule = vm.PassphraseRule;
        s.PasswordValidityDays = vm.PasswordValidityDays;
        s.SessionTimeoutMinutes = vm.SessionTimeoutMinutes;
        await _users.SaveAsync();
        TempData["ok"] = "Ustawienia zapisane.";
        return RedirectToAction(nameof(Settings));
    }

    
    private async Task<User?> Guard(int id)
    {
        var user = await _users.GetAsync(id);
        if (user == null) return null;
        if (user.IsBuiltin || user.Id == Me!.Id)
        {
            TempData["error"] = "Ta operacja nie jest dozwolona dla tego konta.";
            return null;
        }
        return user;
    }
}
