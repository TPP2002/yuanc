using System.Reflection;

namespace WinClient.Core.Client;

/// <summary>测试包开关:程序集元数据带 YuanC.TestBuild=true 时打出的包关闭断网保护,不能交给客户。</summary>
public static class BuildInfo
{
    public const string TestBuildKey = "YuanC.TestBuild";

    internal static bool IsTestBuild(IEnumerable<AssemblyMetadataAttribute> metadata) =>
        metadata.Any(item => item.Key == TestBuildKey && string.Equals(item.Value, "true", StringComparison.OrdinalIgnoreCase));

    public static bool IsTestBuild(Assembly? assembly) =>
        assembly is not null && IsTestBuild(assembly.GetCustomAttributes<AssemblyMetadataAttribute>());

    public static bool TestBuild { get; } = IsTestBuild(Assembly.GetEntryAssembly());

    /// <summary>测试包既不保持保护也不自动连接;正式包除期望明确为断开外照常接回。</summary>
    public static bool KeepOnStartup(bool testBuild, bool? desired) => !testBuild && desired != false;
}
