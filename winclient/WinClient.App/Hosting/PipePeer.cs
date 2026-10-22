using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using WinClient.Core.Ipc;

namespace WinClient.App.Hosting;

/// <summary>
/// 本机管道两端的进程身份：服务端按客户端进程号限连，客户端核验服务端是不是本产品的后台服务。
/// 只调用系统接口查询，不启动任何新进程。
/// </summary>
public static class PipePeer
{
    private const uint ProcessQueryLimitedInformation = 0x1000;

    /// <summary>服务端取连上来的客户端进程号；取不到返回 null。</summary>
    public static uint? ClientProcessId(NamedPipeServerStream pipe)
    {
        try { return NativeMethods.GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var id) && id != 0 ? id : null; }
        catch (Exception ex) when (ex is ObjectDisposedException or InvalidOperationException or IOException) { return null; }
    }

    /// <summary>客户端取管道服务端进程号；取不到返回 null。</summary>
    public static uint? ServerProcessId(NamedPipeClientStream pipe)
    {
        try { return NativeMethods.GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var id) && id != 0 ? id : null; }
        catch (Exception ex) when (ex is ObjectDisposedException or InvalidOperationException or IOException) { return null; }
    }

    /// <summary>按进程号查询程序完整路径（受限查询权限即可）；任一步失败返回 null。</summary>
    public static string? ProcessImage(uint processId)
    {
        if (processId == 0) return null;
        using var process = NativeMethods.OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (process.IsInvalid) return null;
        var buffer = new char[32768];
        var size = (uint)buffer.Length;
        if (!NativeMethods.QueryFullProcessImageNameW(process, 0, buffer, ref size) || size == 0 || size > buffer.Length) return null;
        return new string(buffer, 0, (int)size);
    }

    /// <summary>
    /// 核验已连上的管道服务端：进程在会话 0（系统服务）且程序位于安装目录之下。任一步失败都按不可信处理。
    /// </summary>
    public static bool VerifyServer(NamedPipeClientStream pipe, string appRoot)
    {
        if (ServerProcessId(pipe) is not { } processId) return false;
        var image = ProcessImage(processId);
        if (image is null) return false;
        if (!NativeMethods.ProcessIdToSessionId(processId, out var sessionId)) return false;
        return IsTrustedServer(sessionId, image, appRoot);
    }

    /// <summary>会话 0（系统服务）且程序完整路径严格位于 appRoot 之下；纯判定在 Core 的 ServerIdentity 中实现与单测。</summary>
    public static bool IsTrustedServer(uint sessionId, string? imagePath, string appRoot) =>
        ServerIdentity.IsTrusted(sessionId, ServiceSessionId, imagePath, appRoot);

    private const uint ServiceSessionId = 0;

    private static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern SafeProcessHandle OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, [Out] char[] exeName, ref uint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);
    }
}
