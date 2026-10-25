using System.Net;
using WinClient.Core.Diagnostics;
using Xunit;

namespace WinClient.Tests;

/// <summary>在内存里拼 pcapng 字节与各类数据包,供读取器与归类测试共用。</summary>
internal static class PcapBuilder
{
    public static byte[] Block(uint type, byte[] body, bool bigEndian = false)
    {
        var padded = (body.Length + 3) / 4 * 4;
        var total = 12 + padded;
        var bytes = new byte[total];
        U32(bytes, 0, type, bigEndian);
        U32(bytes, 4, (uint)total, bigEndian);
        Array.Copy(body, 0, bytes, 8, body.Length);
        U32(bytes, total - 4, (uint)total, bigEndian);
        return bytes;
    }

    public static byte[] Shb(bool bigEndian = false)
    {
        var body = new byte[16];
        U32(body, 0, 0x1A2B3C4D, bigEndian);
        U16(body, 4, 1, bigEndian);
        for (var i = 8; i < 16; i++) body[i] = 0xFF; // 节长度未知
        return Block(0x0A0D0D0A, body, bigEndian);
    }

    public static byte[] Idb(int linkType, bool bigEndian = false)
    {
        var body = new byte[8];
        U16(body, 0, (ushort)linkType, bigEndian);
        U32(body, 4, 65535, bigEndian);
        return Block(1, body, bigEndian);
    }

    public static byte[] Epb(byte[] data, int iface = 0, bool bigEndian = false)
    {
        var body = new byte[20 + data.Length];
        U32(body, 0, (uint)iface, bigEndian);
        U32(body, 12, (uint)data.Length, bigEndian);
        U32(body, 16, (uint)data.Length, bigEndian);
        Array.Copy(data, 0, body, 20, data.Length);
        return Block(6, body, bigEndian);
    }

    public static byte[] Spb(byte[] data, bool bigEndian = false)
    {
        var body = new byte[4 + data.Length];
        U32(body, 0, (uint)data.Length, bigEndian);
        Array.Copy(data, 0, body, 4, data.Length);
        return Block(3, body, bigEndian);
    }

    public static byte[] Ipv4(string src, string dst, byte protocol, int srcPort, int dstPort)
    {
        var packet = new byte[20 + 8];
        packet[0] = 0x45;
        packet[9] = protocol;
        IPAddress.Parse(src).GetAddressBytes().CopyTo(packet, 12);
        IPAddress.Parse(dst).GetAddressBytes().CopyTo(packet, 16);
        packet[20] = (byte)(srcPort >> 8); packet[21] = (byte)srcPort;
        packet[22] = (byte)(dstPort >> 8); packet[23] = (byte)dstPort;
        return packet;
    }

    public static byte[] Ipv6(string src, string dst, byte protocol, int srcPort, int dstPort, bool hopByHop = false)
    {
        var extra = hopByHop ? 8 : 0;
        var packet = new byte[40 + extra + 8];
        packet[0] = 0x60;
        packet[6] = hopByHop ? (byte)0 : protocol;
        IPAddress.Parse(src).GetAddressBytes().CopyTo(packet, 8);
        IPAddress.Parse(dst).GetAddressBytes().CopyTo(packet, 24);
        if (hopByHop) { packet[40] = protocol; packet[41] = 0; }
        var t = 40 + extra;
        packet[t] = (byte)(srcPort >> 8); packet[t + 1] = (byte)srcPort;
        packet[t + 2] = (byte)(dstPort >> 8); packet[t + 3] = (byte)dstPort;
        return packet;
    }

    public static byte[] Ethernet(byte[] ip, ushort etherType, bool vlan = false)
    {
        var header = vlan ? 18 : 14;
        var frame = new byte[header + ip.Length];
        if (vlan)
        {
            frame[12] = 0x81; frame[13] = 0x00; frame[14] = 0x00; frame[15] = 0x05;
            frame[16] = (byte)(etherType >> 8); frame[17] = (byte)etherType;
        }
        else { frame[12] = (byte)(etherType >> 8); frame[13] = (byte)etherType; }
        Array.Copy(ip, 0, frame, header, ip.Length);
        return frame;
    }

    public static byte[] EthernetV4(string src, string dst, byte protocol, int srcPort, int dstPort) =>
        Ethernet(Ipv4(src, dst, protocol, srcPort, dstPort), 0x0800);

    public static byte[] File(params byte[][] blocks) => blocks.SelectMany(block => block).ToArray();

    private static void U32(byte[] bytes, int offset, uint value, bool bigEndian)
    {
        if (bigEndian) System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset), value);
        else System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), value);
    }

    private static void U16(byte[] bytes, int offset, ushort value, bool bigEndian)
    {
        if (bigEndian) System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(offset), value);
        else System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(offset), value);
    }
}

public sealed class PcapNgReaderTests
{
    private static List<CapturedPacket> Read(byte[] bytes) => PcapNgReader.Read(new MemoryStream(bytes)).ToList();

    [Fact]
    public void ReadsEthernetIpv4TcpAndUdp()
    {
        var file = PcapBuilder.File(PcapBuilder.Shb(), PcapBuilder.Idb(1),
            PcapBuilder.Epb(PcapBuilder.EthernetV4("192.168.1.5", "8.8.8.8", 6, 50000, 443)),
            PcapBuilder.Epb(PcapBuilder.EthernetV4("192.168.1.5", "74.125.250.129", 17, 50001, 19302)),
            PcapBuilder.Epb(PcapBuilder.EthernetV4("192.168.1.5", "1.1.1.1", 1, 0, 0)),
            PcapBuilder.Epb(PcapBuilder.EthernetV4("192.168.1.5", "1.1.1.1", 47, 0, 0)));
        var packets = Read(file);
        Assert.Equal(4, packets.Count);
        Assert.Equal(new CapturedPacket(1, IPAddress.Parse("192.168.1.5"), IPAddress.Parse("8.8.8.8"), "TCP", 50000, 443), packets[0]);
        Assert.Equal("UDP", packets[1].Protocol);
        Assert.Equal(19302, packets[1].DestinationPort);
        Assert.Equal("ICMP", packets[2].Protocol);
        Assert.Equal("OTHER", packets[3].Protocol);
    }

    [Fact]
    public void ReadsVlanTaggedAndRawIpv6()
    {
        var vlan = PcapBuilder.Ethernet(PcapBuilder.Ipv4("10.0.0.2", "9.9.9.9", 6, 1234, 80), 0x0800, vlan: true);
        var raw = PcapBuilder.Ipv6("2001:db8::1", "2606:4700::1111", 17, 5000, 53, hopByHop: true);
        var raw4 = PcapBuilder.Ipv4("10.0.0.2", "9.9.9.9", 17, 1, 2);
        var file = PcapBuilder.File(PcapBuilder.Shb(), PcapBuilder.Idb(1), PcapBuilder.Idb(229), PcapBuilder.Idb(101),
            PcapBuilder.Epb(vlan, 0), PcapBuilder.Epb(raw, 1), PcapBuilder.Epb(raw4, 2));
        var packets = Read(file);
        Assert.Equal(3, packets.Count);
        Assert.Equal("9.9.9.9", packets[0].Destination!.ToString());
        Assert.Equal(80, packets[0].DestinationPort);
        Assert.Equal(229, packets[1].LinkType);
        Assert.Equal("UDP", packets[1].Protocol);
        Assert.Equal(53, packets[1].DestinationPort);
        Assert.Equal(IPAddress.Parse("2606:4700::1111"), packets[1].Destination);
        Assert.Equal(101, packets[2].LinkType);
        Assert.Equal(2, packets[2].DestinationPort);
    }

    [Fact]
    public void HandlesBigEndianSectionHeader()
    {
        var file = PcapBuilder.File(PcapBuilder.Shb(true), PcapBuilder.Idb(1, true),
            PcapBuilder.Epb(PcapBuilder.EthernetV4("10.1.1.1", "8.8.4.4", 6, 40000, 853), 0, true),
            PcapBuilder.Spb(PcapBuilder.EthernetV4("10.1.1.1", "8.8.4.4", 17, 40001, 53), true));
        var packets = Read(file);
        Assert.Equal(2, packets.Count);
        Assert.Equal("TCP", packets[0].Protocol);
        Assert.Equal(853, packets[0].DestinationPort);
        Assert.Equal("UDP", packets[1].Protocol);
        Assert.Equal(1, packets[1].LinkType);
    }

    [Fact]
    public void SkipsUnknownBlocksAndCountsUnparsed()
    {
        var arp = PcapBuilder.Ethernet(new byte[28], 0x0806);
        var file = PcapBuilder.File(PcapBuilder.Shb(), PcapBuilder.Idb(1),
            PcapBuilder.Block(5, new byte[24]), // 接口统计块,应被跳过
            PcapBuilder.Epb(arp),
            PcapBuilder.Epb(PcapBuilder.EthernetV4("10.1.1.1", "8.8.4.4", 6, 40000, 853)));
        var packets = Read(file);
        Assert.Equal(2, packets.Count);
        Assert.Null(packets[0].Source);
        Assert.Null(packets[0].Destination);
        Assert.NotNull(packets[1].Source);
    }

    [Fact]
    public void RejectsTruncatedBlock()
    {
        var good = PcapBuilder.Epb(PcapBuilder.EthernetV4("10.1.1.1", "8.8.4.4", 6, 1, 2));
        var file = PcapBuilder.File(PcapBuilder.Shb(), PcapBuilder.Idb(1), good.Take(good.Length - 6).ToArray());
        var ex = Assert.Throws<InvalidDataException>(() => Read(file));
        Assert.Equal("抓包文件格式不正确", ex.Message);
        var badLength = PcapBuilder.File(PcapBuilder.Shb(), PcapBuilder.Idb(1), PcapBuilder.Block(6, new byte[24]));
        badLength[badLength.Length - 4] = 0x03; // 篡改块尾长度,不再等于块头长度
        Assert.Throws<InvalidDataException>(() => Read(badLength));
    }
}
