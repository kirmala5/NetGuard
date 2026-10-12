using System.Buffers.Binary;
using System.Net;

namespace NetGuard.Core.Protocols;

/// <summary>
/// Разбор кадра Ethernet и заголовков IP/TCP/UDP/ICMP.
///
/// Требование к классу: разбор **никогда** не бросает исключений. Метаданные
/// берутся из недоверенного канала, и падение на одном испорченном пакете
/// остановило бы файрвол целиком. Любая ошибка трактуется как «не удалось
/// разобрать»: пакет помечается как Other и проверяется только по сетевому
/// уровню (адреса), без портов.
/// </summary>
public static class PacketParser
{
    private const int EthernetHeaderLength = 14;
    private const ushort EtherTypeIpv4 = 0x0800;
    private const ushort EtherTypeIpv6 = 0x86DD;
    private const ushort EtherTypeVlan = 0x8100;
    private const ushort EtherTypeQinQ = 0x88A8;

    public const byte IpProtoTcp = 6;
    public const byte IpProtoUdp = 17;
    public const byte IpProtoIcmp = 1;
    public const byte IpProtoIcmpV6 = 58;

    /// <summary>Разбирает буфер кадра. offset — начало кадра в буфере.</summary>
    public static PacketInfo Parse(ReadOnlySpan<byte> buffer, int offset, int length, bool isOutbound)
    {
        if (length <= 0 || offset < 0 || offset + length > buffer.Length)
            return PacketInfo.Empty;

        var frame = buffer.Slice(offset, length);

        return ParseEthernet(frame, isOutbound);
    }

    private static PacketInfo ParseEthernet(ReadOnlySpan<byte> frame, bool isOutbound)
    {
        // Минимальный кадр без VLAN: 14 байт заголовка + 20 байт IPv4.
        if (frame.Length < EthernetHeaderLength + 20)
            return PacketInfo.Empty;

        ushort etherType = BinaryPrimitives.ReadUInt16BigEndian(frame[12..]);

        int ipOffset = EthernetHeaderLength;

        // Метки VLAN 802.1Q / QinQ добавляют по 4 байта и могут быть вложены.
        int guard = 0;
        while ((etherType == EtherTypeVlan || etherType == EtherTypeQinQ) && guard++ < 2)
        {
            if (frame.Length < ipOffset + 4)
                return PacketInfo.Empty;

            etherType = BinaryPrimitives.ReadUInt16BigEndian(frame[(ipOffset + 2)..]);
            ipOffset += 4;
        }

        var info = etherType switch
        {
            EtherTypeIpv4 => ParseIpv4(frame[ipOffset..], isOutbound),
            EtherTypeIpv6 => ParseIpv6(frame[ipOffset..], isOutbound),
            _ => PacketInfo.Empty,
        };

        // Проставляем информацию о кадре: она нужна для расширенного лога
        // и для будущей фильтрации по MAC.
        return info with
        {
            IsEthernet = true,
            EtherType = etherType,
        };
    }

    private static PacketInfo ParseIpv4(ReadOnlySpan<byte> ip, bool isOutbound)
    {
        if (ip.Length < 20)
            return PacketInfo.Empty;

        int versionAndIhl = ip[0];
        int version = versionAndIhl >> 4;
        int headerLength = (versionAndIhl & 0x0F) * 4;

        if (version != 4 || headerLength < 20 || ip.Length < headerLength)
            return PacketInfo.Empty;

        int totalLength = BinaryPrimitives.ReadUInt16BigEndian(ip[2..]);
        if (totalLength < headerLength)
            return PacketInfo.Empty;

        // Обрезаем по Total Length: кадр может быть дополнен до минимума 64 байта.
        int available = Math.Min(ip.Length, totalLength);
        var body = ip[..available];
        var payload = body[headerLength..];

        ushort fragmentField = BinaryPrimitives.ReadUInt16BigEndian(ip[6..]);
        bool moreFragments = (fragmentField & 0x2000) != 0;
        int fragmentOffset = fragmentField & 0x1FFF;
        bool isFragment = moreFragments || fragmentOffset != 0;

        byte protocol = ip[9];

        var source = new IPAddress(ip.Slice(12, 4));
        var destination = new IPAddress(ip.Slice(16, 4));

        if (isFragment)
        {
            // У фрагмента, кроме первого, транспортного заголовка нет —
            // порты выглядели бы случайными числами и давали бы неверные срабатывания.
            return new PacketInfo(
                IsEthernet: false, EtherType: EtherTypeIpv4, IsIpv6: false,
                Protocol: MapProtocol(protocol, false), SourceAddress: source, DestinationAddress: destination,
                SourcePort: 0, DestinationPort: 0, HasPorts: false, IcmpType: 0, IcmpCode: 0,
                IsFragment: true, IpHeaderLength: headerLength, TransportHeaderLength: 0,
                PayloadLength: payload.Length);
        }

        var (transport, transportHeaderLength) = ParseTransport(protocol, false, payload);

        // Адреса обязательно переносим из сетевого заголовка: результат
        // разбора транспортного уровня содержит только порты, и без
        // переноса правила по адресам не совпали бы никогда.
        return transport with
        {
            EtherType = EtherTypeIpv4,
            IsIpv6 = false,
            SourceAddress = source,
            DestinationAddress = destination,
            IpHeaderLength = headerLength,
            PayloadLength = Math.Max(0, available - headerLength - transportHeaderLength),
        };
    }

    private static PacketInfo ParseIpv6(ReadOnlySpan<byte> ip, bool isOutbound)
    {
        // Базовый заголовок IPv6 всегда 40 байт.
        if (ip.Length < 40)
            return PacketInfo.Empty;

        int version = ip[0] >> 4;
        if (version != 6)
            return PacketInfo.Empty;

        int payloadLength = BinaryPrimitives.ReadUInt16BigEndian(ip[4..]);
        byte nextHeader = ip[6];

        var source = new IPAddress(ip.Slice(8, 16));
        var destination = new IPAddress(ip.Slice(24, 16));

        int total = 40 + payloadLength;
        if (total <= 0 || total > ip.Length)
            total = ip.Length;

        var afterHeader = ip[40..total];

        // Проходим по цепочке расширяющих заголовков: транспортный протокол
        // может быть указан не сразу после базового заголовка.
        int offset = 0;
        byte protocol = nextHeader;
        bool isFragment = false;
        int extensionBytes = 0;
        int guard = 0;

        while (IsExtensionHeader(protocol) && guard++ < 8)
        {
            if (offset + 8 > afterHeader.Length)
                return BuildIpv6(source, destination, ProtocolNumber.Other, 0, 0, false, 40, 0,
                    Math.Max(0, afterHeader.Length));

            byte following = afterHeader[offset];

            switch (protocol)
            {
                case 0:   // Hop-by-Hop Options
                case 43:  // Routing
                case 60:  // Destination Options
                    {
                    // HdrExtLen — длина в 8-байтных единицах без первых 8 байт.
                    int length = (afterHeader[offset + 1] + 1) * 8;
                    offset += length;
                    extensionBytes += length;
                    break;
                    }

                case 44:  // Fragment
                    {
                    int fragmentField = BinaryPrimitives.ReadUInt16BigEndian(afterHeader[(offset + 2)..]);
                    isFragment = (fragmentField & 0xFFF8) != 0;   // M-флаг и смещение
                    offset += 8;
                    extensionBytes += 8;
                    break;
                    }

                case 51:  // Authentication Header — длина в 4-байтных единицах + 2
                    {
                    int length = (afterHeader[offset + 1] + 2) * 4;
                    offset += length;
                    extensionBytes += length;
                    break;
                    }

                default:
                    return BuildIpv6(source, destination, ProtocolNumber.Other, 0, 0, isFragment, 40,
                        extensionBytes, Math.Max(0, afterHeader.Length));
            }

            if (offset > afterHeader.Length)
                return BuildIpv6(source, destination, ProtocolNumber.Other, 0, 0, isFragment, 40,
                    extensionBytes, Math.Max(0, afterHeader.Length));

            protocol = following;
        }

        var payload = afterHeader[offset..];

        if (isFragment)
        {
            return BuildIpv6(source, destination, MapProtocol(protocol, true), 0, 0, true,
                40, extensionBytes, payload.Length);
        }

        var (transport, transportHeaderLength) = ParseTransport(protocol, true, payload);

        return transport with
        {
            EtherType = EtherTypeIpv6,
            IsIpv6 = true,
            SourceAddress = source,
            DestinationAddress = destination,
            IpHeaderLength = 40 + extensionBytes,
            PayloadLength = Math.Max(0, payload.Length - transportHeaderLength),
        };
    }

    private static PacketInfo BuildIpv6(
        IPAddress source, IPAddress destination, ProtocolNumber protocol,
        ushort sourcePort, ushort destinationPort, bool isFragment,
        int ipHeaderLength, int transportHeaderLength, int payloadLength) =>
        new(
            IsEthernet: false, EtherType: EtherTypeIpv6, IsIpv6: true, Protocol: protocol,
            SourceAddress: source, DestinationAddress: destination,
            SourcePort: sourcePort, DestinationPort: destinationPort,
            HasPorts: false, IcmpType: 0, IcmpCode: 0, IsFragment: isFragment,
            IpHeaderLength: ipHeaderLength, TransportHeaderLength: transportHeaderLength,
            PayloadLength: payloadLength);

    private static bool IsExtensionHeader(byte protocol) =>
        protocol is 0 or 43 or 44 or 51 or 60;

    private static (PacketInfo Info, int HeaderLength) ParseTransport(
        byte protocol, bool isIpv6, ReadOnlySpan<byte> payload)
    {
        switch (protocol)
        {
            case IpProtoTcp:
                return ParseTcp(payload);

            case IpProtoUdp:
                return ParseUdp(payload);

            case IpProtoIcmp:
                return (ParseIcmp(payload, isIpv6: false), 0);

            case IpProtoIcmpV6:
                return (ParseIcmp(payload, isIpv6: true), 0);

            default:
                return (PacketInfo.Empty, 0);
        }
    }

    private static (PacketInfo, int) ParseTcp(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 20)
            return (PacketInfo.Empty, 0);

        // DataOffset — старшие 4 бита 12-го байта, длина в 4-байтных единицах.
        int headerLength = (payload[12] >> 4) * 4;

        if (headerLength < 20 || payload.Length < headerLength)
            return (PacketInfo.Empty, 0);

        ushort sourcePort = BinaryPrimitives.ReadUInt16BigEndian(payload[0..]);
        ushort destinationPort = BinaryPrimitives.ReadUInt16BigEndian(payload[2..]);

        var info = new PacketInfo(
            IsEthernet: false, EtherType: 0, IsIpv6: false, Protocol: ProtocolNumber.Tcp,
            SourceAddress: null, DestinationAddress: null,
            SourcePort: sourcePort, DestinationPort: destinationPort,
            HasPorts: true, IcmpType: 0, IcmpCode: 0, IsFragment: false,
            IpHeaderLength: 0, TransportHeaderLength: headerLength, PayloadLength: 0);

        return (info, headerLength);
    }

    private static (PacketInfo, int) ParseUdp(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 8)
            return (PacketInfo.Empty, 0);

        ushort sourcePort = BinaryPrimitives.ReadUInt16BigEndian(payload[0..]);
        ushort destinationPort = BinaryPrimitives.ReadUInt16BigEndian(payload[2..]);

        var info = new PacketInfo(
            IsEthernet: false, EtherType: 0, IsIpv6: false, Protocol: ProtocolNumber.Udp,
            SourceAddress: null, DestinationAddress: null,
            SourcePort: sourcePort, DestinationPort: destinationPort,
            HasPorts: true, IcmpType: 0, IcmpCode: 0, IsFragment: false,
            IpHeaderLength: 0, TransportHeaderLength: 8, PayloadLength: 0);

        return (info, 8);
    }

    private static PacketInfo ParseIcmp(ReadOnlySpan<byte> payload, bool isIpv6)
    {
        // ICMP и ICMPv6 имеют одинаковые первые 4 байта: type, code, checksum.
        if (payload.Length < 4)
            return PacketInfo.Empty;

        return new PacketInfo(
            IsEthernet: false, EtherType: 0, IsIpv6: isIpv6,
            Protocol: isIpv6 ? ProtocolNumber.IcmpV6 : ProtocolNumber.Icmp,
            SourceAddress: null, DestinationAddress: null,
            SourcePort: 0, DestinationPort: 0, HasPorts: false,
            IcmpType: payload[0], IcmpCode: payload[1], IsFragment: false,
            IpHeaderLength: 0, TransportHeaderLength: 0, PayloadLength: 0);
    }

    private static ProtocolNumber MapProtocol(byte protocol, bool isIpv6) => protocol switch
    {
        IpProtoTcp => ProtocolNumber.Tcp,
        IpProtoUdp => ProtocolNumber.Udp,
        IpProtoIcmp => isIpv6 ? ProtocolNumber.IcmpV6 : ProtocolNumber.Icmp,
        IpProtoIcmpV6 => ProtocolNumber.IcmpV6,
        _ => ProtocolNumber.Other,
    };
}