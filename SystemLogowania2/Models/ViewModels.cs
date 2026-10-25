namespace SystemLogowania2.Models;

public class LoginVm
{
    public string? Username { get; set; }
    public string? Password { get; set; }
}

public class ChangePasswordVm
{
    public string? OldPassword { get; set; }
    public string? NewPassword { get; set; }
    public string? NewPassword2 { get; set; }
    public bool Forced { get; set; }
    public bool Rule { get; set; }
}

public class UserFormVm
{
    public int? Id { get; set; }
    public string? Username { get; set; }
    public string? Role { get; set; }
}

public class OtpVm
{
    public string Username { get; set; } = "";
    public string Otp { get; set; } = "";
    public int Hours { get; set; }
}

public class SettingsVm
{
    public bool PassphraseRule { get; set; }
    public int PasswordValidityDays { get; set; }
    public int SessionTimeoutMinutes { get; set; }
}
