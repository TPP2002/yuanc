using System.Text.RegularExpressions;
using WinClient.Core.Client;
using Xunit;

namespace WinClient.Tests;

public sealed class AppScopeTests
{
    private const string Local = @"C:\Users\u\AppData\Local";
    internal static readonly AppScopeFolders Folders = new(@"C:\Windows", @"C:\Program Files", @"C:\Program Files (x86)", Local,
        @"C:\Users\u\AppData\Roaming", @"C:\Users\u", @"C:\ProgramData");

    private sealed class FakeFs(params string[] files) : IAppScopeFileSystem
    {
        public List<string> Roots { get; } = [];
        public int Limit { get; private set; }
        public Exception? Error { get; init; }
        public IReadOnlyList<string> EnumerateExecutables(string root, int maxDepth, int limit)
        {
            Roots.Add(root); Limit = limit;
            if (Error is not null) throw Error;
            return files.Where(file => file.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase)).Take(limit).ToArray();
        }
    }

    private static bool Matches(string pattern, string path) =>
        Regex.IsMatch(path, pattern.Replace("(?i)", ""), RegexOptions.IgnoreCase);

    [Fact]
    public void ExpandsVersionedSquirrelLayoutToParent()
    {
        var selected = Local + @"\Discord\app-1.0.9\Discord.exe";
        var fs = new FakeFs(selected, Local + @"\Discord\Update.exe", Local + @"\Discord\app-1.0.9\helper.exe");
        var scope = AppScopeResolver.Resolve(selected, Folders, fs);
        Assert.True(scope.Expanded);
        Assert.Equal(Local + @"\Discord", Assert.Single(fs.Roots));
        Assert.Equal(AppScopeResolver.MaxExecutables + 1, fs.Limit);
        Assert.True(Matches(scope.Pattern, Local + @"\Discord\Update.exe"));
        Assert.True(Matches(scope.Pattern, Local + @"\Discord\app-1.0.10\Discord.exe"));
        Assert.False(Matches(scope.Pattern, Local + @"\Other\x.exe"));
        Assert.Equal(3, scope.Executables.Count);
        Assert.Equal(scope.Executables.Order(StringComparer.OrdinalIgnoreCase), scope.Executables);
    }

    [Fact]
    public void ExpandsPlainInstallDirectory()
    {
        const string dir = @"C:\Program Files (x86)\Google\Chrome\Application";
        var selected = dir + @"\chrome.exe";
        var fs = new FakeFs(selected, dir + @"\chrome_proxy.exe", dir + @"\123.0.1\elevation_service.exe");
        var scope = AppScopeResolver.Resolve(selected, Folders, fs);
        Assert.True(scope.Expanded);
        Assert.Equal(dir, Assert.Single(fs.Roots));
        Assert.True(Matches(scope.Pattern, dir + @"\chrome_proxy.exe"));
        Assert.False(Matches(scope.Pattern, @"C:\Program Files (x86)\Google\Chrome\Other\x.exe"));
        Assert.Equal(3, scope.Executables.Count);
    }

    [Fact]
    public void GeneralizesMsixPackageVersion()
    {
        const string packages = @"C:\Program Files\WindowsApps";
        var selected = packages + @"\Claude_1.2.3.0_x64__pzs8sxrjxfjjc\app\claude.exe";
        var fs = new FakeFs(selected, packages + @"\Claude_1.2.3.0_x64__pzs8sxrjxfjjc\app\helper.exe");
        var scope = AppScopeResolver.Resolve(selected, Folders, fs);
        Assert.True(scope.Expanded);
        Assert.Equal(packages + @"\Claude_1.2.3.0_x64__pzs8sxrjxfjjc", Assert.Single(fs.Roots));
        Assert.True(Matches(scope.Pattern, packages + @"\Claude_1.3.0.0_x64__pzs8sxrjxfjjc\app\claude.exe"));
        Assert.False(Matches(scope.Pattern, packages + @"\Other_1.0.0.0_x64__abc\x.exe"));
        Assert.False(Matches(scope.Pattern, packages + @"\Claude_1.3.0.0_x64__other\app\claude.exe"));
    }

    [Theory]
    [InlineData(@"C:\Windows\System32\curl.exe")]
    [InlineData(@"C:\Tools\curl.exe")]
    [InlineData(@"C:\Program Files\app.exe")]
    [InlineData(@"C:\Users\u\AppData\Local\x.exe")]
    [InlineData(@"C:\x.exe")]
    [InlineData(@"C:\Program Files\WindowsApps\x.exe")]
    public void DoesNotExpandBroadOrSystemDirectories(string selected)
    {
        var fs = new FakeFs(selected, Path.GetDirectoryName(selected) + @"\other.exe");
        var scope = AppScopeResolver.Resolve(selected, Folders, fs);
        Assert.False(scope.Expanded);
        Assert.Equal(RoutingRenderer.PathPattern(selected), scope.Pattern);
        Assert.Equal(selected, Assert.Single(scope.Executables));
        Assert.Empty(fs.Roots);
    }

    [Fact]
    public void FallsBackWhenTooManyExecutables()
    {
        const string dir = @"C:\Apps\Big\bin";
        var files = Enumerable.Range(0, 65).Select(i => $@"{dir}\f{i:00}.exe").ToArray();
        var scope = AppScopeResolver.Resolve(files[0], Folders, new FakeFs(files));
        Assert.False(scope.Expanded);
        Assert.Equal(files[0], Assert.Single(scope.Executables));
        var exact = AppScopeResolver.Resolve(files[0], Folders, new FakeFs(files.Take(64).ToArray()));
        Assert.True(exact.Expanded);
        Assert.Equal(64, exact.Executables.Count);
    }

    [Fact]
    public void FallsBackWhenEnumerationFails()
    {
        const string selected = @"C:\Apps\Big\bin\x.exe";
        var scope = AppScopeResolver.Resolve(selected, Folders, new FakeFs { Error = new UnauthorizedAccessException() });
        Assert.False(scope.Expanded);
        Assert.Equal(RoutingRenderer.PathPattern(selected), scope.Pattern);
        Assert.Equal(selected, Assert.Single(scope.Executables));
    }

    [Fact]
    public void PatternEscapesMetacharacters()
    {
        const string dir = @"C:\Apps\My App (x86)\C++ Tool";
        const string selected = dir + @"\a.exe";
        var scope = AppScopeResolver.Resolve(selected, Folders, new FakeFs(selected));
        Assert.Equal(@"(?i)^C:\\Apps\\My App \(x86\)\\C\+\+ Tool\\.+\.exe$", scope.Pattern);
        Assert.True(Matches(scope.Pattern, dir + @"\b.exe"));
        Assert.False(Matches(scope.Pattern, @"C:\Apps\My App x86\C Tool\b.exe"));
        Assert.Equal(RoutingRenderer.PathPattern(selected), AppScope.Exact(selected).Pattern);
    }

    [Fact]
    public void DeduplicatesSelectedCaseInsensitively()
    {
        const string selected = @"C:\Apps\Tool\a.exe";
        var scope = AppScopeResolver.Resolve(selected, Folders, new FakeFs(@"C:\Apps\Tool\A.EXE", @"C:\Apps\Tool\b.exe"));
        Assert.Equal(2, scope.Executables.Count);
    }
}
