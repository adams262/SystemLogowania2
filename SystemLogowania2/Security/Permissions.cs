namespace SystemLogowania2.Security;

/// <summary>Role z wariantu 6.</summary>
public static class Roles
{
    public const string Administrator = "Administrator";
    public const string Manager = "Kierownik";
    public const string Editor = "Redaktor";
    public const string Reader = "Czytelnik";

    public static readonly string[] All = { Administrator, Manager, Editor, Reader };
}

/// <summary>
/// Warstwa uprawnień. Kod aplikacji sprawdza UPRAWNIENIA (polityki autoryzacji),
/// nigdy nazwy ról - nowe moduły dopisują uprawnienia tylko tutaj.
/// </summary>
public static class Permissions
{
    public const string UsersManage = "users.manage";
    public const string SettingsManage = "settings.manage";
    public const string ContentRead = "content.read";
    public const string ContentWrite = "content.write";
    public const string ContentApprove = "content.approve";

    public static readonly IReadOnlyDictionary<string, string> Labels = new Dictionary<string, string>
    {
        [UsersManage] = "Zarządzanie użytkownikami",
        [SettingsManage] = "Zmiana ustawień bezpieczeństwa",
        [ContentRead] = "Przeglądanie treści",
        [ContentWrite] = "Tworzenie i edycja treści",
        [ContentApprove] = "Zatwierdzanie treści",
    };

    public static IEnumerable<string> All => Labels.Keys;

    private static readonly Dictionary<string, HashSet<string>> ByRole = new()
    {
        [Roles.Administrator] = new(Labels.Keys),
        [Roles.Manager] = new() { ContentRead, ContentWrite, ContentApprove },
        [Roles.Editor] = new() { ContentRead, ContentWrite },
        [Roles.Reader] = new() { ContentRead },
    };

    public static IEnumerable<string> For(string? role) =>
        role != null && ByRole.TryGetValue(role, out var set) ? set : Enumerable.Empty<string>();

    public static bool Has(string? role, string permission) =>
        role != null && ByRole.TryGetValue(role, out var set) && set.Contains(permission);
}
