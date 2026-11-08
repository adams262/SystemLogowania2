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
    public bool IsBuiltin { get; set; }          
    public bool MustChange { get; set; } = true; 
    public DateTime? OneTimeExpires { get; set; } 
    public DateTime PasswordChangedAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public int FailedAttempts { get; set; }      
    public DateTime? LockedUntil { get; set; }   
    public bool IsCanary { get; set; }
}

public class PasswordHistory
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string PasswordHash { get; set; } = "";
    public string Salt { get; set; } = "";
    public DateTime CreatedAt { get; set; }
}


public class SecuritySettings
{
    public int Id { get; set; }
    public bool PassphraseRule { get; set; }          
    public int PasswordValidityDays { get; set; } = 90; 
    public int SessionTimeoutMinutes { get; set; } = 15;
    public int MaxFailedAttempts { get; set; } = 5;   
    public int IpMaxAttempts { get; set; } = 10;
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

    public DbSet<LoginAttempt> LoginAttempts => Set<LoginAttempt>();
    public DbSet<SecurityEvent> SecurityEvents => Set<SecurityEvent>();
}

public class LoginAttempt      
{
    public int Id { get; set; }
    public string Ip { get; set; } = "";
    public DateTime At { get; set; }
}

public class SecurityEvent     
{
    public int Id { get; set; }
    public DateTime At { get; set; }
    public string Type { get; set; } = "";
    public string Ip { get; set; } = "";
    public string Details { get; set; } = "";
}
