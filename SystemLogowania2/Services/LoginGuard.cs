using SystemLogowania2.Data;
using Microsoft.EntityFrameworkCore;


namespace SystemLogowania2.Services
{
    public class LoginGuard
    {
        public const int LockMinutes = 15;
        private readonly AppDb _db;
        public LoginGuard(AppDb db) => _db = db;

        // --- blokada konta po błędnych próbach ---
        public static TimeSpan? RemainingLock(User u) =>
            u.LockedUntil is DateTime t && t > DateTime.UtcNow ? t - DateTime.UtcNow : null;

        public async Task RegisterFailureAsync(User u, int max)
        {
            if (u.LockedUntil is DateTime t && t <= DateTime.UtcNow)   // stara blokada wygasła
            { u.LockedUntil = null; u.FailedAttempts = 0; }
            u.FailedAttempts++;
            if (u.FailedAttempts >= max)
            {
                u.LockedUntil = DateTime.UtcNow.AddMinutes(LockMinutes);
                u.FailedAttempts = 0;
            }
            await _db.SaveChangesAsync();
        }

        public async Task RegisterSuccessAsync(User u)
        {
            u.FailedAttempts = 0;
            u.LockedUntil = null;
            await _db.SaveChangesAsync();
        }

        // --- zadanie dodatkowe: limit prób z jednego adresu IP ---
        public Task<int> IpFailuresAsync(string ip)
        {
            var since = DateTime.UtcNow.AddMinutes(-LockMinutes);
            return _db.LoginAttempts.CountAsync(a => a.Ip == ip && a.At > since);
        }

        public async Task AddIpFailureAsync(string ip)
        {
            _db.LoginAttempts.Add(new LoginAttempt { Ip = ip, At = DateTime.UtcNow });
            await _db.SaveChangesAsync();
        }

        // --- alerty (honeypot, canary tokens) ---
        public async Task AlertAsync(string type, string ip, string details)
        {
            _db.SecurityEvents.Add(new SecurityEvent
            { At = DateTime.UtcNow, Type = type, Ip = ip, Details = details });
            await _db.SaveChangesAsync();
            Console.WriteLine($"[ALERT {type}] ip={ip} {details}");
        }

        public Task<List<SecurityEvent>> RecentAsync() =>
            _db.SecurityEvents.OrderByDescending(e => e.Id).Take(100).ToListAsync();
    }
}
