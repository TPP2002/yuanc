using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace WinClient.Core.Firewall;

// 声明依据：本机 Windows SDK 10.0.22621.0，结构体使用 SDK 默认对齐。
[SupportedOSPlatform("windows")]
internal static class WfpNative
{
    private const string Library = "fwpuclnt.dll";
    internal const uint RPC_C_AUTHN_WINNT = 10; // shared/rpcdce.h
    internal const uint FWPM_PROVIDER_FLAG_PERSISTENT = 1; // shared/fwpmtypes.h
    internal const uint FWPM_SUBLAYER_FLAG_PERSISTENT = 1; // shared/fwpmtypes.h
    internal const uint FWPM_FILTER_FLAG_PERSISTENT = 1; // shared/fwpmtypes.h
    internal const int FWP_E_FILTER_NOT_FOUND = unchecked((int)0x80320003); // shared/winerror.h
    internal const int FWP_E_PROVIDER_NOT_FOUND = unchecked((int)0x80320005); // shared/winerror.h
    internal const int FWP_E_SUBLAYER_NOT_FOUND = unchecked((int)0x80320007); // shared/winerror.h
    internal const int FWP_E_ALREADY_EXISTS = unchecked((int)0x80320009); // shared/winerror.h
    internal const uint FWP_UINT8 = 1; // shared/fwptypes.h: FWP_DATA_TYPE
    internal const uint FWP_UINT16 = 2; // shared/fwptypes.h
    internal const uint FWP_UINT32 = 3; // shared/fwptypes.h
    internal const uint FWP_BYTE_BLOB_TYPE = 12; // shared/fwptypes.h
    internal const uint FWP_V4_ADDR_MASK = 0x100; // shared/fwptypes.h
    internal const uint FWP_V6_ADDR_MASK = 0x101; // shared/fwptypes.h
    internal const uint FWP_MATCH_EQUAL = 0; // shared/fwptypes.h: FWP_MATCH_TYPE
    internal const uint FWP_MATCH_FLAGS_ALL_SET = 6; // shared/fwptypes.h
    internal const uint FWP_CONDITION_FLAG_IS_LOOPBACK = 1; // shared/fwptypes.h
    internal const uint FWP_ACTION_BLOCK = 0x1001; // shared/fwptypes.h: 1 | FWP_ACTION_FLAG_TERMINATING
    internal const uint FWP_ACTION_PERMIT = 0x1002; // shared/fwptypes.h: 2 | FWP_ACTION_FLAG_TERMINATING
    internal const uint FWP_FILTER_ENUM_FULLY_CONTAINED = 0; // shared/fwptypes.h
    internal const uint FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED = 0x10; // shared/fwptypes.h
    internal const byte IPPROTO_TCP = 6; // shared/ws2def.h
    internal const byte IPPROTO_UDP = 17; // shared/ws2def.h

    internal static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82"); // um/fwpmu.h
    internal static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4"); // um/fwpmu.h
    internal static readonly Guid FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 = new("e1cd9fe7-f4b5-4273-96c0-592e487b8650"); // um/fwpmu.h
    internal static readonly Guid FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 = new("a3b42c97-9f04-4672-b87e-cee9c483257f"); // um/fwpmu.h
    internal static readonly Guid FWPM_CONDITION_ALE_APP_ID = new("d78e1e87-8644-4ea5-9437-d809ecefc971"); // um/fwpmu.h
    internal static readonly Guid FWPM_CONDITION_IP_REMOTE_ADDRESS = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045"); // um/fwpmu.h
    internal static readonly Guid FWPM_CONDITION_IP_LOCAL_ADDRESS = new("d9ee00de-c1ef-4617-bfe3-ffd8f5a08957"); // um/fwpmu.h
    internal static readonly Guid FWPM_CONDITION_IP_PROTOCOL = new("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7"); // um/fwpmu.h
    internal static readonly Guid FWPM_CONDITION_IP_LOCAL_PORT = new("0c1ba1af-5765-453f-af22-a8f791ac775b"); // um/fwpmu.h
    internal static readonly Guid FWPM_CONDITION_IP_REMOTE_PORT = new("c35a604d-d22b-4e1a-91b4-68f674ee674b"); // um/fwpmu.h
    internal static readonly Guid FWPM_CONDITION_FLAGS = new("632ce23b-5167-435c-86d7-e903684aa80c"); // um/fwpmu.h

    // shared/fwptypes.h：指针与小整数共用联合体，自动按当前进程指针宽度对齐。
    [StructLayout(LayoutKind.Explicit)]
    internal struct FWP_VALUE_UNION
    {
        [FieldOffset(0)] internal byte uint8;
        [FieldOffset(0)] internal ushort uint16;
        [FieldOffset(0)] internal uint uint32;
        [FieldOffset(0)] internal IntPtr pointer;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_VALUE0 { internal uint type; internal FWP_VALUE_UNION value; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_CONDITION_VALUE0 { internal uint type; internal FWP_VALUE_UNION value; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_V4_ADDR_AND_MASK { internal uint addr; internal uint mask; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_V6_ADDR_AND_MASK
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] internal byte[] addr;
        internal byte prefixLength;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_BYTE_BLOB { internal uint size; internal IntPtr data; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_DISPLAY_DATA0 { internal IntPtr name; internal IntPtr description; }

    // shared/fwpmtypes.h：字符串和可选 GUID 均是指针，由调用方管理生存期。
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_SESSION0
    {
        internal Guid sessionKey;
        internal FWPM_DISPLAY_DATA0 displayData;
        internal uint flags, txnWaitTimeoutInMSec, processId;
        internal IntPtr sid, username;
        internal int kernelMode;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_PROVIDER0
    {
        internal Guid providerKey;
        internal FWPM_DISPLAY_DATA0 displayData;
        internal uint flags;
        internal FWP_BYTE_BLOB providerData;
        internal IntPtr serviceName;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_SUBLAYER0
    {
        internal Guid subLayerKey;
        internal FWPM_DISPLAY_DATA0 displayData;
        internal uint flags;
        internal IntPtr providerKey;
        internal FWP_BYTE_BLOB providerData;
        internal ushort weight;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_ACTION0 { internal uint type; internal Guid filterType; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_FILTER_CONDITION0
    {
        internal Guid fieldKey;
        internal uint matchType;
        internal FWP_CONDITION_VALUE0 conditionValue;
    }
    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal struct FWPM_CONTEXT_UNION
    {
        [FieldOffset(0)] internal ulong rawContext;
        [FieldOffset(0)] internal Guid providerContextKey;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_FILTER0
    {
        internal Guid filterKey;
        internal FWPM_DISPLAY_DATA0 displayData;
        internal uint flags;
        internal IntPtr providerKey;
        internal FWP_BYTE_BLOB providerData;
        internal Guid layerKey, subLayerKey;
        internal FWP_VALUE0 weight;
        internal uint numFilterConditions;
        internal IntPtr filterCondition;
        internal FWPM_ACTION0 action;
        internal FWPM_CONTEXT_UNION context;
        internal IntPtr reserved;
        internal ulong filterId;
        internal FWP_VALUE0 effectiveWeight;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_FILTER_ENUM_TEMPLATE0
    {
        internal IntPtr providerKey;
        internal Guid layerKey;
        internal uint enumType, flags;
        internal IntPtr providerContextTemplate;
        internal uint numFilterConditions;
        internal IntPtr filterCondition;
        internal uint actionMask;
        internal IntPtr calloutKey;
    }

    // um/fwpmu.h：DWORD 返回值直接保留位模式，不读取 GetLastError。
    [DllImport(Library, ExactSpelling = true, CharSet = CharSet.Unicode)]
    internal static extern int FwpmEngineOpen0(string? serverName, uint authnService, IntPtr authIdentity, in FWPM_SESSION0 session, out IntPtr engineHandle);
    [DllImport(Library, ExactSpelling = true)] internal static extern int FwpmEngineClose0(IntPtr engineHandle);
    [DllImport(Library, ExactSpelling = true)] internal static extern int FwpmTransactionBegin0(IntPtr engineHandle, uint flags);
    [DllImport(Library, ExactSpelling = true)] internal static extern int FwpmTransactionCommit0(IntPtr engineHandle);
    [DllImport(Library, ExactSpelling = true)] internal static extern int FwpmTransactionAbort0(IntPtr engineHandle);
    [DllImport(Library, ExactSpelling = true)] internal static extern int FwpmProviderAdd0(IntPtr engineHandle, in FWPM_PROVIDER0 provider, IntPtr sd);
    [DllImport(Library, ExactSpelling = true)] internal static extern int FwpmProviderDeleteByKey0(IntPtr engineHandle, in Guid key);
    [DllImport(Library, ExactSpelling = true)] internal static extern int FwpmSubLayerAdd0(IntPtr engineHandle, in FWPM_SUBLAYER0 subLayer, IntPtr sd);
    [DllImport(Library, ExactSpelling = true)] internal static extern int FwpmSubLayerDeleteByKey0(IntPtr engineHandle, in Guid key);
    [DllImport(Library, ExactSpelling = true)] internal static extern int FwpmFilterAdd0(IntPtr engineHandle, in FWPM_FILTER0 filter, IntPtr sd, out ulong id);
    [DllImport(Library, ExactSpelling = true)] internal static extern int FwpmFilterDeleteById0(IntPtr engineHandle, ulong id);
    [DllImport(Library, ExactSpelling = true)] internal static extern int FwpmFilterCreateEnumHandle0(IntPtr engineHandle, in FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate, out IntPtr enumHandle);
    [DllImport(Library, ExactSpelling = true)] internal static extern int FwpmFilterEnum0(IntPtr engineHandle, IntPtr enumHandle, uint numEntriesRequested, out IntPtr entries, out uint numEntriesReturned);
    [DllImport(Library, ExactSpelling = true)] internal static extern int FwpmFilterDestroyEnumHandle0(IntPtr engineHandle, IntPtr enumHandle);
    [DllImport(Library, ExactSpelling = true, CharSet = CharSet.Unicode)] internal static extern int FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);
    [DllImport(Library, ExactSpelling = true)] internal static extern void FwpmFreeMemory0(ref IntPtr memory);
}
