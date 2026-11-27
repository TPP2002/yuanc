using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WinClient.Core.Process;

/// <summary>
/// 把连接内核放进「关闭即结束」的作业对象：后台服务进程一没，内核跟着被系统结束。
/// 作业句柄不可继承——句柄一旦可继承，内核经重定向输出继承后会自己攥着作业，服务死了作业也不关。
/// </summary>
public sealed class KernelJob : IDisposable
{
    private const uint JobObjectExtendedLimitInformation = 9;
    private const uint JobObjectLimitKillOnJobClose = 0x2000;

    private readonly SafeJobHandle handle;

    private KernelJob(SafeJobHandle handle) => this.handle = handle;

    public static KernelJob Create()
    {
        // 安全属性传 IntPtr.Zero、名字传 null：作业句柄不可继承。
        var raw = CreateJobObjectW(IntPtr.Zero, null);
        if (raw == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        var safe = new SafeJobHandle(raw);
        try
        {
            var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION
            {
                BasicLimitInformation = new JOBOBJECT_BASIC_LIMIT_INFORMATION
                {
                    LimitFlags = JobObjectLimitKillOnJobClose
                }
            };
            var size = Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(info, buffer, false);
                if (!SetInformationJobObject(safe, JobObjectExtendedLimitInformation, buffer, (uint)size))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally { Marshal.FreeHGlobal(buffer); }
            return new KernelJob(safe);
        }
        catch
        {
            safe.Dispose();
            throw;
        }
    }

    public void Assign(System.Diagnostics.Process process)
    {
        ArgumentNullException.ThrowIfNull(process);
        if (!AssignProcessToJobObject(handle, process.SafeHandle))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    public bool Contains(System.Diagnostics.Process process)
    {
        ArgumentNullException.ThrowIfNull(process);
        if (!IsProcessInJob(process.SafeHandle, handle, out var result))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return result;
    }

    public void Dispose() => handle.Dispose();

    private sealed class SafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeJobHandle(IntPtr handle) : base(ownsHandle: true) => SetHandle(handle);
        protected override bool ReleaseHandle() => CloseHandle(handle);
    }

    // shared/jobapi.h 与 winnt.h：结构体按 SDK 默认对齐。
    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        internal long PerProcessUserTimeLimit;
        internal long PerJobUserTimeLimit;
        internal uint LimitFlags;
        internal UIntPtr MinimumWorkingSetSize;
        internal UIntPtr MaximumWorkingSetSize;
        internal uint ActiveProcessLimit;
        internal UIntPtr Affinity;
        internal uint PriorityClass;
        internal uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        internal ulong ReadOperationCount;
        internal ulong WriteOperationCount;
        internal ulong OtherOperationCount;
        internal ulong ReadTransferCount;
        internal ulong WriteTransferCount;
        internal ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        internal JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        internal IO_COUNTERS IoInfo;
        internal UIntPtr ProcessMemoryLimit;
        internal UIntPtr JobMemoryLimit;
        internal UIntPtr PeakProcessMemoryUsed;
        internal UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern IntPtr CreateJobObjectW(IntPtr jobAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(SafeJobHandle job, uint infoClass, IntPtr info, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(SafeJobHandle job, SafeProcessHandle process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsProcessInJob(SafeProcessHandle process, SafeJobHandle job, out bool result);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
