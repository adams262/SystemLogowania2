using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SystemLogowania2.Services;


public static class Passwords
{
    
    public const int MinLength = 15;      
    public const int MinWords = 3;       
    public const int OtpLength = 12;      
    public const int OtpValidHours = 48;  

    private const string Letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string Digits = "0123456789";
    public const string Specials = "!@#$%^&*()-_=+[]{};:,.?";

    private const int Iterations = 600_000;

    public static (string Hash, string Salt) Hash(string password, byte[]? salt = null)
    {
        salt ??= RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password), salt, Iterations, HashAlgorithmName.SHA256, 32);
        return (Convert.ToHexString(hash), Convert.ToHexString(salt));
    }

    public static bool Verify(string password, string hashHex, string saltHex)
    {
        var (calc, _) = Hash(password, Convert.FromHexString(saltHex));
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(calc), Encoding.ASCII.GetBytes(hashHex));
    }

    
    public static List<string> Validate(string password, bool passphraseRule)
    {
        var errors = new List<string>();
        if (password.Length < MinLength)
            errors.Add($"Hasło musi mieć co najmniej {MinLength} znaków.");
        if (passphraseRule)
        {
            var words = Regex.Split(password.Trim(), "[ -]+").Count(w => w.Length > 0);
            if (words < MinWords)
                errors.Add($"Hasło musi być frazą co najmniej {MinWords} słów oddzielonych spacją lub myślnikiem.");
        }
        return errors;
    }

    
    public static string GenerateOtp()
    {
        var all = Letters + Digits + Specials;
        var chars = new List<char> { Pick(Letters), Pick(Digits), Pick(Specials) };
        while (chars.Count < OtpLength) chars.Add(Pick(all));
        for (var i = chars.Count - 1; i > 0; i--) 
        {
            var j = RandomNumberGenerator.GetInt32(i + 1);
            (chars[i], chars[j]) = (chars[j], chars[i]);
        }
        return new string(chars.ToArray());
    }

    private static char Pick(string set) => set[RandomNumberGenerator.GetInt32(set.Length)];
}
