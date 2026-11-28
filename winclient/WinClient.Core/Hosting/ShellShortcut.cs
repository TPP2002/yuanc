using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.Versioning;
using System.Text;

namespace WinClient.Core.Hosting;

/// <summary>读写 .lnk 快捷方式：只用系统自带的 ShellLink 组件，不额外拉起任何程序。</summary>
[SupportedOSPlatform("windows")]
public static class ShellShortcut
{
    public sealed record Link(string Target, string Arguments, string WorkingDirectory, string Description);

    public static void Write(string linkPath, Link link)
    {
        var shell = (IShellLinkW)new ShellLinkObject();
        try
        {
            shell.SetPath(link.Target);
            shell.SetArguments(link.Arguments);
            shell.SetWorkingDirectory(link.WorkingDirectory);
            shell.SetDescription(link.Description);
            shell.SetIconLocation(link.Target, 0);
            ((IPersistFile)shell).Save(linkPath, true);
        }
        finally
        {
            Marshal.FinalReleaseComObject(shell);
        }
    }

    public static Link? Read(string linkPath)
    {
        if (!File.Exists(linkPath)) return null;
        var shell = (IShellLinkW)new ShellLinkObject();
        try
        {
            ((IPersistFile)shell).Load(linkPath, 0);

            var buffer = new StringBuilder(1024);
            shell.GetPath(buffer, 1024, IntPtr.Zero, 0);
            var target = buffer.ToString();

            buffer = new StringBuilder(1024);
            shell.GetArguments(buffer, 1024);
            var arguments = buffer.ToString();

            buffer = new StringBuilder(1024);
            shell.GetWorkingDirectory(buffer, 1024);
            var workingDirectory = buffer.ToString();

            buffer = new StringBuilder(1024);
            shell.GetDescription(buffer, 1024);
            return new Link(target, arguments, workingDirectory, buffer.ToString());
        }
        finally
        {
            Marshal.FinalReleaseComObject(shell);
        }
    }

    [ComImport, Guid("00021401-0000-0000-C000-000000000046")]
    private class ShellLinkObject { }

    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("000214F9-0000-0000-C000-000000000046")]
    private interface IShellLinkW
    {
        void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder file, int capacity, IntPtr findData, uint flags);
        void GetIDList(out IntPtr list);
        void SetIDList(IntPtr list);
        void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder name, int capacity);
        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string name);
        void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder directory, int capacity);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string directory);
        void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder arguments, int capacity);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string arguments);
        void GetHotkey(out short hotkey);
        void SetHotkey(short hotkey);
        void GetShowCmd(out int show);
        void SetShowCmd(int show);
        void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder path, int capacity, out int index);
        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string path, int index);
        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string path, uint reserved);
        void Resolve(IntPtr window, uint flags);
        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string file);
    }
}
