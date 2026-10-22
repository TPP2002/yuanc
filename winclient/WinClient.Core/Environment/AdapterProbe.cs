using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace WinClient.Core.EnvironmentSupport;

public sealed record AdapterAddress(string Address, int PrefixLength);
public sealed record AdapterInfo(string Name, string Description, IReadOnlyList<AdapterAddress> Ipv4);

public interface IAdapterProbe
{
    IReadOnlyList<AdapterInfo>? Snapshot();
}

public sealed class SystemAdapterProbe : IAdapterProbe
{
    public IReadOnlyList<AdapterInfo>? Snapshot()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(adapter => adapter.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Select(adapter => new AdapterInfo(adapter.Name, adapter.Description,
                    adapter.GetIPProperties().UnicastAddresses
                        .Where(address => address.Address.AddressFamily == AddressFamily.InterNetwork)
                        .Select(address => new AdapterAddress(address.Address.ToString(), address.PrefixLength)).ToArray()))
                .ToArray();
        }
        catch (Exception ex) when (ex is NetworkInformationException or PlatformNotSupportedException or InvalidOperationException)
        {
            return null;
        }
    }
}
