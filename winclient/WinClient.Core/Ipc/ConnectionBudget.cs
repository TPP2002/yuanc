namespace WinClient.Core.Ipc;

/// <summary>
/// 本机管道连接预算：总数与每个客户端进程的连接数都有上限，防止单个程序占满全部管道实例。
/// 纯逻辑、线程安全；超额时返回 false 且不计数。
/// </summary>
public sealed class ConnectionBudget
{
    private readonly object gate = new();
    private readonly Dictionary<uint, int> perClient = [];
    private readonly int maxTotal;
    private readonly int maxPerClient;
    private int active;

    public ConnectionBudget(int maxTotal, int maxPerClient)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxTotal, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxPerClient, 1);
        this.maxTotal = maxTotal;
        this.maxPerClient = maxPerClient;
    }

    public int Active { get { lock (gate) return active; } }

    public bool TryAdmit(uint clientProcessId)
    {
        lock (gate)
        {
            if (active >= maxTotal) return false;
            perClient.TryGetValue(clientProcessId, out var count);
            if (count >= maxPerClient) return false;
            perClient[clientProcessId] = count + 1;
            active++;
            return true;
        }
    }

    public void Release(uint clientProcessId)
    {
        lock (gate)
        {
            // 未登记的进程号直接忽略，重复释放不会把计数减成负数。
            if (!perClient.TryGetValue(clientProcessId, out var count)) return;
            if (count <= 1) perClient.Remove(clientProcessId);
            else perClient[clientProcessId] = count - 1;
            active--;
        }
    }
}
