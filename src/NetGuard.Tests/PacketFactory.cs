using System.Buffers.Binary;
using NetGuard.Core.Protocols;

namespace NetGuard.Tests;

/// <summary>
/// Синтезирует пакеты для проверки разбора заголовков.
/// Собрано вручную по RFC 791 (IPv4), RFC 8200 (IPv6), RFC 793 (TCP),
/// RFC 768 (UDP), RFC 792 (ICMP) — чтобы тесты не зависели от захвата
/// реального трафика, который в среде сборки недоступен.
/// </summary>
internal static class PacketFactory
{
    /// <summary>Ethernet + IPv4 + TCP.</summary>
    public static byte[] EthernetIpv4Tcp(
        string src = "10.0.0.1", string dst = "93.184.216.34",
        ushort srcPort = 51515, ushort dstPort = 443,
        int ipOptionsBytes = 0, bool moreFragments = false, ushort fragmentOffset = 0,
        ushort etherType = 0x0800, bool vlan = false)
    {
        int ipHeaderLength = 20 + ipOptionsBytes;
        var ip = new byte[ipHeaderLength];

        // version 4 в старших 4 битах, IHL — длина заголовка в 4-байтных единицах.
        ip[0] = (byte)(0x40 | (ipHeaderLength / 4));
        ip[1] = 0x00;
        int totalLength = ipHeaderLength + 20;          // + TCP header
        BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(2), (ushort)totalLength);
        BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(4), 0x1234);
        ushort frag = 0;
        if (moreFragments) frag |= 0x2000;
        frag |= fragmentOffset;
        BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(6), frag);
        ip[8] = 64;                                    // TTL
        ip[9] = 6;                                     // TCP
        WriteIpv4(ip, 12, src);
        WriteIpv4(ip, 16, dst);

        var tcp = new byte[20];
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(0), srcPort);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(2), dstPort);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.AsSpan(4), 0x11223344);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.AsSpan(8), 0x55667788);
        tcp[12] = 0x50;                                // data offset 5 words, no options
        tcp[13] = 0x18;                                // PSH | ACK

        return Frame(etherType, vlan, ip, tcp);
    }

    /// <summary>Ethernet + IPv4 + UDP.</summary>
    public static byte[] EthernetIpv4Udp(
        string src = "10.0.0.1", string dst = "8.8.8.8",
        ushort srcPort = 40000, ushort dstPort = 53)
    {
        var ip = new byte[20];
        ip[0] = 0x45;
        int totalLength = 20 + 8 + 4;
        BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(2), (ushort)totalLength);
        ip[8] = 64;
        ip[9] = 17;                                    // UDP
        WriteIpv4(ip, 12, src);
        WriteIpv4(ip, 16, dst);

        var udp = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(0), srcPort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(2), dstPort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(4), 12);

        return Frame(0x0800, ip, udp);
    }

    /// <summary>Ethernet + IPv4 + ICMP (echo request).</summary>
    public static byte[] EthernetIpv4Icmp(
        string src = "192.168.1.10", string dst = "192.168.1.1",
        byte type = 8, byte code = 0)
    {
        var ip = new byte[20];
        ip[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(2), (ushort)(20 + 8));
        ip[8] = 64;
        ip[9] = 1;                                     // ICMP
        WriteIpv4(ip, 12, src);
        WriteIpv4(ip, 16, dst);

        var icmp = new byte[8];
        icmp[0] = type;
        icmp[1] = code;

        return Frame(0x0800, ip, icmp);
    }

    /// <summary>Ethernet + IPv6 + TCP.</summary>
    public static byte[] EthernetIpv6Tcp(
        string src = "2001:db8::1", string dst = "2606:2800:220:1:248:1893:25c8:1946",
        ushort srcPort = 49152, ushort dstPort = 80)
    {
        var ip = new byte[40];
        ip[0] = 0x60;                                  // version 6
        BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(4), (ushort)(20 + 20));
        ip[6] = 6;                                     // next header TCP
        ip[7] = 64;                                    // hop limit
        WriteIpv6(ip, 8, src);
        WriteIpv6(ip, 24, dst);

        var tcp = new byte[20];
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(0), srcPort);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(2), dstPort);
        tcp[12] = 0x50;
        tcp[13] = 0x10;                                // ACK

        return Frame(0x86DD, ip, tcp);
    }

    /// <summary>IPv6 с одним заголовком Hop-by-Hop перед TCP.</summary>
    public static byte[] EthernetIpv6WithHopByHopThenTcp(ushort dstPort = 443)
    {
        var ip = new byte[40];
        ip[0] = 0x60;
        ip[6] = 0;                                     // next header = Hop-by-Hop
        ip[7] = 64;

        // Payload Length обязателен: без него разбор не найдёт расширяющие
        // заголовки и вернёт «Other».
        BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(4), (ushort)(8 + 20));

        WriteIpv6(ip, 8, "2001:db8::1");
        WriteIpv6(ip, 24, "2001:db8::2");

        // Hop-by-Hop: next header = TCP, HdrExtLen = 0 (8 байт целиком).
        var hbh = new byte[8];
        hbh[0] = 6;
        hbh[1] = 0;

        var tcp = new byte[20];
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(0), 1234);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(2), dstPort);
        tcp[12] = 0x50;

        return Frame(0x86DD, ip, hbh, tcp);
    }

    private static byte[] Frame(ushort etherType, params byte[][] parts) =>
        Frame(etherType, vlan: false, parts);

    /// <summary>
    /// Собирает кадр Ethernet. При vlan=true добавляется метка 802.1Q
    /// (4 байта) — парсер обязан её учесть при поиске IP-заголовка.
    /// </summary>
    private static byte[] Frame(ushort etherType, bool vlan, params byte[][] parts)
    {
        const int EthHeaderLength = 14;
        const int VlanHeaderLength = 18;

        int headerLength = vlan ? VlanHeaderLength : EthHeaderLength;
        int payloadLength = parts.Sum(p => p.Length);

        var frame = new byte[headerLength + payloadLength];

        if (vlan)
        {
            BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(12), 0x8100);  // TPID
            BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(14), 0x0064);  // VLAN id 100
            BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(16), etherType);
        }
        else
        {
            BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(12), etherType);
        }

        int offset = headerLength;
        foreach (var part in parts)
        {
            part.CopyTo(frame.AsSpan(offset));
            offset += part.Length;
        }

        return frame;
    }

    private static void WriteIpv4(byte[] buffer, int offset, string address) =>
        System.Net.IPAddress.Parse(address).GetAddressBytes()
            .CopyTo(buffer.AsSpan(offset));

    private static void WriteIpv6(byte[] buffer, int offset, string address) =>
        System.Net.IPAddress.Parse(address).GetAddressBytes()
            .CopyTo(buffer.AsSpan(offset));
}