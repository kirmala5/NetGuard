namespace NetGuard.Core.Protocols;

/// <summary>Транспортный протокол, разобранный из заголовка пакета.</summary>
public enum ProtocolNumber
{
    Unknown = 0,
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
    Other,
}

/// <summary>Направление пакета относительно машины.</summary>
public enum TrafficDirection
{
    /// <summary>Пакет уходит с машины.</summary>
    Outbound,

    /// <summary>Пакет приходит на машину.</summary>
    Inbound,

    /// <summary>Направление определить не удалось (например, пакет без заголовков).</summary>
    Unknown,
}

/// <summary>Результат разбора одного пакета.</summary>
/// <param name="IsEthernet">Пакет начинается с заголовка Ethernet (в WinDivert — всегда).</param>
/// <param name="EtherType">Тип кадра: 0x0800 IPv4, 0x86DD IPv6, 0x8100 VLAN и т. п.</param>
/// <param name="IsIpv6">Признак IPv6 (иначе IPv4).</param>
/// <param name="Protocol">Транспортный протокол.</param>
/// <param name="SourceAddress">IP-адрес источника.</summary>
/// <param name="DestinationAddress">IP-адрес получателя.</param>
/// <param name="SourcePort">Порт источника; 0, если транспортного порта нет (ICMP) или заголовок не разобран.</param>
/// <param name="DestinationPort">Порт получателя.</param>
/// <param name="HasPorts">Есть ли корректные порты для сопоставления с правилом.</param>
/// <param name="IcmpType">Тип сообщения ICMP/ICMPv6.</param>
/// <param name="IcmpCode">Код сообщения ICMP/ICMPv6.</param>
/// <param name="IsFragment">Пакет является фрагментом: транспортный заголовок может отсутствовать.</param>
/// <param name="IpHeaderLength">Длина заголовка сетевого уровня в байтах.</param>
/// <param name="TransportHeaderLength">Длина транспортного заголовка в байтах.</param>
/// <param name="PayloadLength">Длина полезной нагрузки в байтах.</param>
public readonly record struct PacketInfo(
    bool IsEthernet,
    ushort EtherType,
    bool IsIpv6,
    ProtocolNumber Protocol,
    System.Net.IPAddress? SourceAddress,
    System.Net.IPAddress? DestinationAddress,
    ushort SourcePort,
    ushort DestinationPort,
    bool HasPorts,
    byte IcmpType,
    byte IcmpCode,
    bool IsFragment,
    int IpHeaderLength,
    int TransportHeaderLength,
    int PayloadLength)
{
    /// <summary>Пустой результат для нераспознанного пакета.</summary>
    public static PacketInfo Empty { get; } = new(
        IsEthernet: false, EtherType: 0, IsIpv6: false, Protocol: ProtocolNumber.Other,
        SourceAddress: null, DestinationAddress: null, SourcePort: 0, DestinationPort: 0,
        HasPorts: false, IcmpType: 0, IcmpCode: 0, IsFragment: false,
        IpHeaderLength: 0, TransportHeaderLength: 0, PayloadLength: 0);

    /// <summary>Краткое описание протокола для журнала и интерфейсов.</summary>
    public string ProtocolName => Protocol switch
    {
        ProtocolNumber.Tcp => "TCP",
        ProtocolNumber.Udp => "UDP",
        ProtocolNumber.Icmp => "ICMP",
        ProtocolNumber.IcmpV6 => "ICMPv6",
        _ => "OTHER",
    };
}