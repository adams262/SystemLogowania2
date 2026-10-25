using SystemLogowania2.Security;
using Microsoft.EntityFrameworkCore;

namespace SystemLogowania2.Data;

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public string Salt { get; set; } = "";
    public string Role { get; set; } = Roles.Reader;
    public bool IsBlocked { get; set; }
    public bool IsBuiltin { get; set; }          // stałe konto ADMIN
    public bool MustChange { get; set; } = true; // wymuszona zmiana hasła
    public DateTime? OneTimeExpires { get; set; } // ważność hasła jednorazowego (UTC)
    public DateTime PasswordChangedAt { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class PasswordHistory
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string PasswordHash { get; set; } = "";
    public string Salt { get; set; } = "";
    public DateTime CreatedAt { get; set; }
}

/// <summary>Ustawienia ustawiane przez administratora (jeden wiersz).</summary>
public class SecuritySettings
{
    public int Id { get; set; }
    public bool PassphraseRule { get; set; }          // polityka haseł z wariantu
    public int PasswordValidityDays { get; set; } = 90; // 0 = bezterminowo
    public int SessionTimeoutMinutes { get; set; } = 15;
}

public class AppDb : DbContext
{
    public AppDb(DbContextOptions<AppDb> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<PasswordHistory> PasswordHistory => Set<PasswordHistory>();
    public DbSet<SecuritySettings> Settings => Set<SecuritySettings>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<User>().Property(u => u.Username).UseCollation("NOCASE");
        b.Entity<User>().HasIndex(u => u.Username).IsUnique();
        b.Entity<PasswordHistory>()
            .HasOne<User>().WithMany().HasForeignKey(h => h.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
