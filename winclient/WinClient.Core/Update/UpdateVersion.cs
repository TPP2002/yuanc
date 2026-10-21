using System.Numerics;
using System.Text.RegularExpressions;

namespace WinClient.Core.Update;

public sealed class UpdateVersion : IComparable<UpdateVersion>
{
    public const string Pattern = @"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?";
    public string Value { get; }
    private readonly BigInteger[] release;
    private readonly string[] pre;
    public UpdateVersion(string value)
    {
        if (value is null || !Regex.IsMatch(value, @"\A" + Pattern + @"\z"))
            throw new InvalidDataException("客户端版本号不正确。");
        Value = value;
        var parts = value.Split('-', 2);
        release = parts[0].Split('.').Select(BigInteger.Parse).ToArray();
        pre = parts.Length == 1 ? [] : parts[1].Split('.');
    }
    public int CompareTo(UpdateVersion? other)
    {
        if (other is null) return 1;
        for (var i = 0; i < 3; i++)
        {
            var comparison = release[i].CompareTo(other.release[i]);
            if (comparison != 0) return comparison;
        }
        if (pre.Length == 0 || other.pre.Length == 0) return (pre.Length == 0).CompareTo(other.pre.Length == 0);
        for (var i = 0; i < Math.Min(pre.Length, other.pre.Length); i++)
        {
            var numberA = BigInteger.TryParse(pre[i], out var a) && pre[i].All(char.IsAsciiDigit);
            var numberB = BigInteger.TryParse(other.pre[i], out var b) && other.pre[i].All(char.IsAsciiDigit);
            var comparison = numberA && numberB ? a.CompareTo(b) : numberA != numberB
                ? numberB.CompareTo(numberA) : string.CompareOrdinal(pre[i], other.pre[i]);
            if (comparison != 0) return comparison;
        }
        return pre.Length.CompareTo(other.pre.Length);
    }
    public override string ToString() => Value;
}
