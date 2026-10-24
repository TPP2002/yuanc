using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using static WinClient.Core.Firewall.WfpNative;

namespace WinClient.Core.Firewall;

public interface IWfpEngine
{
    void Install(IReadOnlyList<WfpFilterSpec> filters);
    void Remove();
    IReadOnlyList<string> ListFilterNames();
}

public sealed class WfpException : Exception
{
    public WfpException(string operation, int hresult) : base($"{operation}: 0x{unchecked((uint)hresult):X8}")
        => HResult = hresult;
}

[SupportedOSPlatform("windows")]
public sealed class WfpEngine(Guid providerKey, Guid sublayerKey, string displayName, bool persistent) : IWfpEngine
{
    public static readonly Guid ProductionProviderKey = new("49ba4101-50c7-486e-80d0-979345e10a22");
    public static readonly Guid ProductionSublayerKey = new("ffef6964-a2ff-45c3-a939-f39ac090e98e");
    public static IWfpEngine? CreateProduction() => OperatingSystem.IsWindows()
        ? new WfpEngine(ProductionProviderKey, ProductionSublayerKey, "YuanC 断网保护", persistent: true) : null;

    public void Install(IReadOnlyList<WfpFilterSpec> filters) => WithEngine(engine =>
    {
        using var memory = new NativeMemory();
        // 应用标识与条件缓冲区必须活到提交或中止之后。
        Transaction(engine, () =>
        {
            var provider = new FWPM_PROVIDER0
            {
                providerKey = providerKey,
                displayData = new() { name = memory.Text(displayName) },
                flags = persistent ? FWPM_PROVIDER_FLAG_PERSISTENT : 0
            };
            Check(FwpmProviderAdd0(engine, in provider, IntPtr.Zero), nameof(FwpmProviderAdd0), FWP_E_ALREADY_EXISTS);
            var providerPointer = memory.Struct(providerKey);
            var sublayer = new FWPM_SUBLAYER0
            {
                subLayerKey = sublayerKey, providerKey = providerPointer,
                displayData = provider.displayData, weight = 0xFFFF,
                flags = persistent ? FWPM_SUBLAYER_FLAG_PERSISTENT : 0
            };
            Check(FwpmSubLayerAdd0(engine, in sublayer, IntPtr.Zero), nameof(FwpmSubLayerAdd0), FWP_E_ALREADY_EXISTS);
            DeleteFilters(engine);
            foreach (var spec in filters)
            {
                var conditions = Conditions(spec, memory);
                var filter = new FWPM_FILTER0
                {
                    providerKey = providerPointer, subLayerKey = sublayerKey, layerKey = LayerKey(spec.Layer),
                    displayData = new() { name = memory.Text(spec.Name) },
                    flags = persistent ? FWPM_FILTER_FLAG_PERSISTENT : 0,
                    weight = new() { type = FWP_UINT8, value = new() { uint8 = spec.Weight } },
                    action = new() { type = spec.Action switch
                    {
                        WfpAction.Permit => FWP_ACTION_PERMIT,
                        WfpAction.Block => FWP_ACTION_BLOCK,
                        _ => throw new ArgumentException("过滤动作无效。")
                    } },
                    numFilterConditions = (uint)conditions.Count,
                    filterCondition = memory.Array(conditions)
                };
                Check(FwpmFilterAdd0(engine, in filter, IntPtr.Zero, out _), nameof(FwpmFilterAdd0));
            }
        });
    });

    public void Remove() => WithEngine(engine => Transaction(engine, () =>
    {
        DeleteFilters(engine);
        Check(FwpmSubLayerDeleteByKey0(engine, in sublayerKey), nameof(FwpmSubLayerDeleteByKey0), FWP_E_SUBLAYER_NOT_FOUND);
        Check(FwpmProviderDeleteByKey0(engine, in providerKey), nameof(FwpmProviderDeleteByKey0), FWP_E_PROVIDER_NOT_FOUND);
    }));

    public IReadOnlyList<string> ListFilterNames()
    {
        var names = new List<string>();
        WithEngine(engine => names.AddRange(Enumerate(engine).Select(filter => filter.Name)));
        return names.AsReadOnly();
    }

    private void DeleteFilters(IntPtr engine)
    {
        foreach (var filter in Enumerate(engine))
            Check(FwpmFilterDeleteById0(engine, filter.Id), nameof(FwpmFilterDeleteById0), FWP_E_FILTER_NOT_FOUND);
    }

    // 枚举模板的 layerKey 不能留空(实测 FWP_E_LAYER_NOT_FOUND),逐层列举。
    private List<(ulong Id, string Name)> Enumerate(IntPtr engine) =>
        Enum.GetValues<WfpLayer>().SelectMany(layer => Enumerate(engine, LayerKey(layer))).ToList();

    private List<(ulong Id, string Name)> Enumerate(IntPtr engine, Guid layerKey)
    {
        using var memory = new NativeMemory();
        var template = new FWPM_FILTER_ENUM_TEMPLATE0
        {
            providerKey = memory.Struct(providerKey),
            layerKey = layerKey,
            enumType = FWP_FILTER_ENUM_FULLY_CONTAINED,
            flags = FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED,
            actionMask = uint.MaxValue
        };
        var result = new List<(ulong, string)>();
        var error = FwpmFilterCreateEnumHandle0(engine, in template, out var enumeration);
        if (error == FWP_E_PROVIDER_NOT_FOUND) return result;
        Check(error, nameof(FwpmFilterCreateEnumHandle0));
        var succeeded = false;
        try
        {
            while (true)
            {
                var entries = IntPtr.Zero;
                try
                {
                    Check(FwpmFilterEnum0(engine, enumeration, 128, out entries, out var count), nameof(FwpmFilterEnum0));
                    if (count == 0) break;
                    for (var i = 0; i < count; i++)
                    {
                        var filter = Marshal.PtrToStructure<FWPM_FILTER0>(Marshal.ReadIntPtr(entries, checked(i * IntPtr.Size)));
                        // 模板已限定提供者；删除入口再核归属，不接触其他提供者的对象。
                        if (filter.providerKey != IntPtr.Zero && Marshal.PtrToStructure<Guid>(filter.providerKey) == providerKey)
                            result.Add((filter.filterId, Marshal.PtrToStringUni(filter.displayData.name) ?? ""));
                    }
                }
                finally { if (entries != IntPtr.Zero) FwpmFreeMemory0(ref entries); }
            }
            succeeded = true;
            return result;
        }
        finally
        {
            var close = FwpmFilterDestroyEnumHandle0(engine, enumeration);
            if (succeeded) Check(close, nameof(FwpmFilterDestroyEnumHandle0));
        }
    }

    private static List<FWPM_FILTER_CONDITION0> Conditions(WfpFilterSpec spec, NativeMemory memory)
    {
        var conditions = new List<FWPM_FILTER_CONDITION0>();
        if (spec.AppPath is not null)
            conditions.Add(Condition(FWPM_CONDITION_ALE_APP_ID, FWP_BYTE_BLOB_TYPE, new() { pointer = memory.AppId(spec.AppPath) }));
        // 同字段条件连续排列，Windows 按或匹配这些地址。
        if (spec.RemoteAddresses is not null)
        {
            if (spec.RemoteAddresses.Length == 0) throw new ArgumentException("过滤远端地址不能为空。");
            foreach (var address in spec.RemoteAddresses)
                conditions.Add(Address(FWPM_CONDITION_IP_REMOTE_ADDRESS, address, spec.Layer, memory));
        }
        if (spec.LocalAddress is not null)
            conditions.Add(Address(FWPM_CONDITION_IP_LOCAL_ADDRESS, spec.LocalAddress, spec.Layer, memory));
        if (spec.Protocol is not null)
            conditions.Add(Condition(FWPM_CONDITION_IP_PROTOCOL, FWP_UINT8, new() { uint8 = spec.Protocol switch
            {
                "TCP" => IPPROTO_TCP, "UDP" => IPPROTO_UDP, _ => throw new ArgumentException("过滤协议无效。")
            } }));
        if (spec.LocalPort is not null) conditions.Add(Port(FWPM_CONDITION_IP_LOCAL_PORT, spec.LocalPort.Value));
        if (spec.RemotePort is not null) conditions.Add(Port(FWPM_CONDITION_IP_REMOTE_PORT, spec.RemotePort.Value));
        if (spec.Loopback)
            conditions.Add(Condition(FWPM_CONDITION_FLAGS, FWP_UINT32,
                new() { uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK }, FWP_MATCH_FLAGS_ALL_SET));
        return conditions;
    }

    private static FWPM_FILTER_CONDITION0 Condition(Guid key, uint type, FWP_VALUE_UNION value, uint match = FWP_MATCH_EQUAL)
        => new() { fieldKey = key, matchType = match, conditionValue = new() { type = type, value = value } };

    private static FWPM_FILTER_CONDITION0 Port(Guid key, int port)
    {
        if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        return Condition(key, FWP_UINT16, new() { uint16 = (ushort)port });
    }

    private static FWPM_FILTER_CONDITION0 Address(Guid key, string value, WfpLayer layer, NativeMemory memory)
    {
        var parts = value.Split('/');
        if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var ip)) throw new ArgumentException("过滤地址无效。");
        var v4 = layer is WfpLayer.ConnectV4 or WfpLayer.AcceptV4;
        if (ip.AddressFamily != (v4 ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6))
            throw new ArgumentException("过滤地址与层不匹配。");
        var bits = v4 ? 32 : 128;
        var prefix = bits;
        if (parts.Length == 2 && (!int.TryParse(parts[1], out prefix) || prefix < 0 || prefix > bits))
            throw new ArgumentException("过滤地址前缀无效。");
        var bytes = ip.GetAddressBytes();
        if (v4)
        {
            var mask = prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
            var address = new FWP_V4_ADDR_AND_MASK { addr = BinaryPrimitives.ReadUInt32BigEndian(bytes) & mask, mask = mask };
            return Condition(key, FWP_V4_ADDR_MASK, new() { pointer = memory.Struct(address) });
        }
        for (var i = 0; i < bytes.Length; i++)
            bytes[i] &= (byte)(0xFF << (8 - Math.Clamp(prefix - i * 8, 0, 8)));
        return Condition(key, FWP_V6_ADDR_MASK,
            new() { pointer = memory.Struct(new FWP_V6_ADDR_AND_MASK { addr = bytes, prefixLength = (byte)prefix }) });
    }

    private static Guid LayerKey(WfpLayer layer) => layer switch
    {
        WfpLayer.ConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        WfpLayer.ConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        WfpLayer.AcceptV4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        WfpLayer.AcceptV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        _ => throw new ArgumentException("过滤层无效。")
    };

    private static void WithEngine(Action<IntPtr> action)
    {
        var session = new FWPM_SESSION0 { txnWaitTimeoutInMSec = 10000 };
        Check(FwpmEngineOpen0(null, RPC_C_AUTHN_WINNT, IntPtr.Zero, in session, out var engine), nameof(FwpmEngineOpen0));
        var succeeded = false;
        try { action(engine); succeeded = true; }
        finally
        {
            var close = FwpmEngineClose0(engine);
            if (succeeded) Check(close, nameof(FwpmEngineClose0));
        }
    }

    private static void Transaction(IntPtr engine, Action action)
    {
        Check(FwpmTransactionBegin0(engine, 0), nameof(FwpmTransactionBegin0));
        var committed = false;
        try
        {
            action();
            Check(FwpmTransactionCommit0(engine), nameof(FwpmTransactionCommit0));
            committed = true;
        }
        finally { if (!committed) FwpmTransactionAbort0(engine); }
    }

    private static void Check(int code, string operation, int allowed = 0)
    {
        if (code != 0 && code != allowed) throw new WfpException(operation, code);
    }

    private sealed class NativeMemory : IDisposable
    {
        private readonly List<IntPtr> allocations = [];
        private readonly List<IntPtr> appIds = [];
        private IntPtr Allocate(int size)
        {
            var pointer = Marshal.AllocHGlobal(size);
            allocations.Add(pointer);
            return pointer;
        }
        internal IntPtr Text(string text)
        {
            var pointer = Marshal.StringToHGlobalUni(text);
            allocations.Add(pointer);
            return pointer;
        }
        internal IntPtr Struct<T>(T value) where T : struct
        {
            var pointer = Allocate(Marshal.SizeOf<T>());
            Marshal.StructureToPtr(value, pointer, false);
            return pointer;
        }
        internal IntPtr Array(List<FWPM_FILTER_CONDITION0> conditions)
        {
            if (conditions.Count == 0) return IntPtr.Zero;
            var size = Marshal.SizeOf<FWPM_FILTER_CONDITION0>();
            var pointer = Allocate(checked(size * conditions.Count));
            for (var i = 0; i < conditions.Count; i++)
                Marshal.StructureToPtr(conditions[i], IntPtr.Add(pointer, checked(i * size)), false);
            return pointer;
        }
        internal IntPtr AppId(string path)
        {
            var result = FwpmGetAppIdFromFileName0(path, out var pointer);
            if (pointer != IntPtr.Zero) appIds.Add(pointer);
            Check(result, nameof(FwpmGetAppIdFromFileName0));
            return pointer;
        }
        public void Dispose()
        {
            foreach (var pointer in appIds) { var owned = pointer; FwpmFreeMemory0(ref owned); }
            foreach (var pointer in allocations) Marshal.FreeHGlobal(pointer);
        }
    }
}
