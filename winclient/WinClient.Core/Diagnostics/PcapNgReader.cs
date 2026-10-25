using System.Buffers.Binary;
using System.Net;

namespace WinClient.Core.Diagnostics;

/// <summary>抓到的一个包。解析不了时 Source / Destination 为 null。</summary>
public sealed record CapturedPacket(int LinkType, IPAddress? Source, IPAddress? Destination, string Protocol, int SourcePort, int DestinationPort);

/// <summary>pcapng 读取器:只认 SHB / IDB / EPB / SPB,其余块跳过。</summary>
public static class PcapNgReader
{
    private const string BadFormat = "抓包文件格式不正确";
    private const uint SectionHeader = 0x0A0D0D0A;
    private const uint InterfaceDescription = 1;
    private const uint SimplePacket = 3;
    private const uint EnhancedPacket = 6;
    private const uint MaxBlock = 256 * 1024 * 1024;

    public static IEnumerable<CapturedPacket> Read(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var links = new List<int>();
        var bigEndian = false;
        var header = new byte[8];
        while (true)
        {
            var got = Fill(stream, header, 8);
            if (got == 0) yield break;
            if (got < 8) throw new InvalidDataException(BadFormat);
            byte[] magic = [];
            uint type;
            if (BinaryPrimitives.ReadUInt32LittleEndian(header) == SectionHeader)
            {
                // 节头类型值是回文,字节序由块体前 4 字节的魔数决定。
                type = SectionHeader;
                magic = new byte[4];
                if (Fill(stream, magic, 4) < 4) throw new InvalidDataException(BadFormat);
                var value = BinaryPrimitives.ReadUInt32LittleEndian(magic);
                if (value == 0x1A2B3C4D) bigEndian = false;
                else if (value == 0x4D3C2B1A) bigEndian = true;
                else throw new InvalidDataException(BadFormat);
                links.Clear();
            }
            else type = ReadU32(header, bigEndian);
            var length = ReadU32(header.AsSpan(4), bigEndian);
            if (length < 12 + magic.Length || length % 4 != 0 || length > MaxBlock) throw new InvalidDataException(BadFormat);
            var rest = new byte[length - 8 - magic.Length];
            if (Fill(stream, rest, rest.Length) < rest.Length) throw new InvalidDataException(BadFormat);
            if (ReadU32(rest.AsSpan(rest.Length - 4), bigEndian) != length) throw new InvalidDataException(BadFormat);
            var body = magic.Concat(rest.Take(rest.Length - 4)).ToArray();
            switch (type)
            {
                case InterfaceDescription:
                    if (body.Length < 8) throw new InvalidDataException(BadFormat);
                    links.Add(ReadU16(body, bigEndian));
                    break;
                case EnhancedPacket:
                    if (body.Length < 20) throw new InvalidDataException(BadFormat);
                    var caplen = ReadU32(body.AsSpan(12), bigEndian);
                    if (caplen > body.Length - 20) throw new InvalidDataException(BadFormat);
                    var iface = ReadU32(body, bigEndian);
                    yield return PacketParser.Parse(iface < links.Count ? links[(int)iface] : 0, body.AsSpan(20, (int)caplen));
                    break;
                case SimplePacket:
                    if (body.Length < 4) throw new InvalidDataException(BadFormat);
                    var original = ReadU32(body, bigEndian);
                    var size = (int)Math.Min(original, (uint)(body.Length - 4));
                    yield return PacketParser.Parse(links.Count > 0 ? links[0] : 0, body.AsSpan(4, size));
                    break;
            }
        }
    }

    private static int ReadU16(byte[] body, bool bigEndian) =>
        bigEndian ? BinaryPrimitives.ReadUInt16BigEndian(body) : BinaryPrimitives.ReadUInt16LittleEndian(body);

    private static int Fill(Stream stream, byte[] buffer, int count)
    {
        var total = 0;
        while (total < count)
        {
            var n = stream.Read(buffer, total, count - total);
            if (n <= 0) break;
            total += n;
        }
        return total;
    }

    private static uint ReadU32(ReadOnlySpan<byte> span, bool bigEndian) =>
        bigEndian ? BinaryPrimitives.ReadUInt32BigEndian(span) : BinaryPrimitives.ReadUInt32LittleEndian(span);
}
