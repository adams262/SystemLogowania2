using SystemLogowania2.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SystemLogowania2.Controllers
{
    [AllowAnonymous]
    public class CanaryController : Controller
    {
        private readonly LoginGuard _guard;
        public CanaryController(LoginGuard guard) => _guard = guard;

        [HttpGet("/backup/hasla_backup.txt")]
        public async Task<IActionResult> Backup()
        {
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "?";
            await _guard.AlertAsync("CANARY-FILE", ip, $"pobranie pliku-pułapki, UA={Request.Headers.UserAgent}");
            // fałszywe dane, prowadzą do konta-pułapki
            return Content("admin.backup : Zima2024!\n", "text/plain");
        }
    }
}
