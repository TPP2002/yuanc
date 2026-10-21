namespace WinClient.Core.Storage;

public interface ICredentialStore
{
    void Save(string refreshToken);
    string? Load();
    void Clear();
}

public sealed class InMemoryCredentialStore : ICredentialStore
{
    private string? value;
    public void Save(string refreshToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(refreshToken);
        value = refreshToken;
    }
    public string? Load() => value;
    public void Clear() => value = null;
}
