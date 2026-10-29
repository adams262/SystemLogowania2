using SystemLogowania2.Data;
using Microsoft.EntityFrameworkCore;

namespace SystemLogowania2.Services;

public class UserService
{
    private readonly AppDb _db;
    public UserService(AppDb db) => _db = db;

    public Task<User?> GetAsync(int id) => _db.Users.FirstOrDefaultAsync(u => u.Id == id);

    
    public Task<User?> FindByNameAsync(string name) =>
        _db.Users.FirstOrDefaultAsync(u => u.Username == name);

    public Task<List<User>> ListAsync() => _db.Users.OrderBy(u => u.Id).ToListAsync();

    public async Task<SecuritySettings> GetSettingsAsync()
    {
        var s = await _db.Settings.FirstOrDefaultAsync();
        if (s == null)
        {
            s = new SecuritySettings();
            _db.Settings.Add(s);
            await _db.SaveChangesAsync();
        }
        return s;
    }

    
    public async Task<(User User, string Otp)> CreateAsync(
        string username, string role, bool builtin = false, string? otp = null)
    {
        otp ??= Passwords.GenerateOtp();
        var (hash, salt) = Passwords.Hash(otp);
        var now = DateTime.UtcNow;
        var user = new User
        {
            Username = username, PasswordHash = hash, Salt = salt, Role = role,
            IsBuiltin = builtin, MustChange = true,
            OneTimeExpires = now.AddHours(Passwords.OtpValidHours),
            PasswordChangedAt = now, CreatedAt = now,
        };
        _db.Users.Add(user);
        await _db.SaveChangesAsync();
        return (user, otp);
    }

    public async Task<string> ResetAsync(User user)
    {
        var otp = Passwords.GenerateOtp();
        (user.PasswordHash, user.Salt) = Passwords.Hash(otp);
        user.MustChange = true;
        user.OneTimeExpires = DateTime.UtcNow.AddHours(Passwords.OtpValidHours);
        user.PasswordChangedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();
        return otp;
    }

    public static bool OtpExpired(User u) => u.OneTimeExpires is DateTime e && DateTime.UtcNow > e;

    public static bool PasswordExpired(User u, SecuritySettings s) =>
        s.PasswordValidityDays > 0 && DateTime.UtcNow > u.PasswordChangedAt.AddDays(s.PasswordValidityDays);

    public static bool NeedsChange(User u, SecuritySettings s) => u.MustChange || PasswordExpired(u, s);

    
    public async Task<bool> IsReusedAsync(User user, string newPassword)
    {
        if (Passwords.Verify(newPassword, user.PasswordHash, user.Salt)) return true;
        var history = await _db.PasswordHistory.Where(h => h.UserId == user.Id).ToListAsync();
        return history.Any(h => Passwords.Verify(newPassword, h.PasswordHash, h.Salt));
    }

    public async Task SetNewPasswordAsync(User user, string newPassword)
    {
        _db.PasswordHistory.Add(new PasswordHistory
        {
            UserId = user.Id, PasswordHash = user.PasswordHash, Salt = user.Salt,
            CreatedAt = DateTime.UtcNow,
        });
        (user.PasswordHash, user.Salt) = Passwords.Hash(newPassword);
        user.MustChange = false;
        user.OneTimeExpires = null;
        user.PasswordChangedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();
    }

    public Task SaveAsync() => _db.SaveChangesAsync();

    public async Task DeleteAsync(User user)
    {
        _db.Users.Remove(user);
        await _db.SaveChangesAsync();
    }
}
