using NetGuard.Core.Protocols;
using Xunit;

namespace NetGuard.Tests;

/// <summary>
/// Проверка разбора заголовков (п. 3.1 ТЗ № 2).
/// Тесты построены на синтетических пакетах: захват реального трафика
/// требует прав администратора и не всегда доступен при сборке.
/// </summary>
public class PacketParserTests
{
    [Fact]
    public void Ipv4Tcp_Разбирает_Адреса_И_Порты()
    {
        var packet = PacketFactory.EthernetIpv4Tcp("10.0.0.1", "93.184.216.34", 51515, 443);

        var info = PacketParser.Parse(packet, 0, packet.Length, isOutbound: true);

        Assert.True(info.IsEthernet);
        Assert.False(info.IsIpv6);
        Assert.Equal(ProtocolNumber.Tcp, info.Protocol);
        Assert.Equal("10.0.0.1", info.SourceAddress?.ToString());
        Assert.Equal("93.184.216.34", info.DestinationAddress?.ToString());
        Assert.Equal(51515, info.SourcePort);
        Assert.Equal(443, info.DestinationPort);
        Assert.True(info.HasPorts);
        Assert.Equal(20, info.IpHeaderLength);
        Assert.Equal(20, info.TransportHeaderLength);
    }

    [Fact]
    public void Ipv4Udp_Разбирает_Порты()
    {
        var packet = PacketFactory.EthernetIpv4Udp("10.0.0.1", "8.8.8.8", 40000, 53);

        var info = PacketParser.Parse(packet, 0, packet.Length, isOutbound: true);

        Assert.Equal(ProtocolNumber.Udp, info.Protocol);
        Assert.Equal(40000, info.SourcePort);
        Assert.Equal(53, info.DestinationPort);
        Assert.Equal(8, info.TransportHeaderLength);
    }

    [Fact]
    public void Icmp_Не_Имеет_Портов_Но_Хранит_Тип_И_Код()
    {
        var packet = PacketFactory.EthernetIpv4Icmp("192.168.1.10", "192.168.1.1", type: 8, code: 0);

        var info = PacketParser.Parse(packet, 0, packet.Length, isOutbound: true);

        Assert.Equal(ProtocolNumber.Icmp, info.Protocol);
        Assert.Equal("ICMP", info.ProtocolName);
        Assert.False(info.HasPorts);
        Assert.Equal(0, info.SourcePort);
        Assert.Equal(8, info.IcmpType);
        Assert.Equal(0, info.IcmpCode);
    }

    [Fact]
    public void Ipv6Tcp_Разбирает_Адреса_И_Порты()
    {
        var packet = PacketFactory.EthernetIpv6Tcp(
            "2001:db8::1", "2606:2800:220:1:248:1893:25c8:1946", 49152, 80);

        var info = PacketParser.Parse(packet, 0, packet.Length, isOutbound: true);

        Assert.True(info.IsIpv6);
        Assert.Equal(ProtocolNumber.Tcp, info.Protocol);
        Assert.Equal("2001:db8::1", info.SourceAddress?.ToString());
        Assert.Equal("2606:2800:220:1:248:1893:25c8:1946", info.DestinationAddress?.ToString());
        Assert.Equal(80, info.DestinationPort);
        Assert.Equal(40, info.IpHeaderLength);
    }

    [Fact]
    public void Ipv6_С_Заголовком_HopByHop_Находит_Транспортный_Протокол()
    {
        var packet = PacketFactory.EthernetIpv6WithHopByHopThenTcp(dstPort: 443);

        var info = PacketParser.Parse(packet, 0, packet.Length, isOutbound: true);

        Assert.True(info.IsIpv6);
        Assert.Equal(ProtocolNumber.Tcp, info.Protocol);
        Assert.Equal(443, info.DestinationPort);
        Assert.Equal(1234, info.SourcePort);

        // 40 байт базового заголовка + 8 байт Hop-by-Hop
        Assert.Equal(48, info.IpHeaderLength);
    }

    [Fact]
    public void Фрагмент_Не_Сообщает_Порты()
    {
        // Второй и последующие фрагменты не содержат транспортного заголовка,
        // поэтому порты в них случайны и не должны участвовать в фильтрации.
        var packet = PacketFactory.EthernetIpv4Tcp(moreFragments: false, fragmentOffset: 185);

        var info = PacketParser.Parse(packet, 0, packet.Length, isOutbound: true);

        Assert.True(info.IsFragment);
        Assert.False(info.HasPorts);
        Assert.Equal(0, info.SourcePort);
        Assert.Equal(0, info.DestinationPort);
    }

    [Fact]
    public void Флаг_MoreFragments_Также_Помечает_Пакет_Фрагментом()
    {
        var packet = PacketFactory.EthernetIpv4Tcp(moreFragments: true);

        var info = PacketParser.Parse(packet, 0, packet.Length, isOutbound: true);

        Assert.True(info.IsFragment);
        Assert.False(info.HasPorts);
    }

    [Fact]
    public void Опции_IP_Учитываются_В_Длине_Заголовка()
    {
        // 4 байта опций => IHL = 6, заголовок 24 байта.
        var packet = PacketFactory.EthernetIpv4Tcp(ipOptionsBytes: 4);

        var info = PacketParser.Parse(packet, 0, packet.Length, isOutbound: true);

        Assert.Equal(24, info.IpHeaderLength);
        Assert.Equal(ProtocolNumber.Tcp, info.Protocol);
        Assert.Equal(443, info.DestinationPort);
    }

    [Fact]
    public void Vlan_Метка_Сдвигает_Начало_IP_Заголовка()
    {
        var packet = PacketFactory.EthernetIpv4Tcp(
            "10.0.0.5", "10.0.0.9", 1234, 80, vlan: true);

        var info = PacketParser.Parse(packet, 0, packet.Length, isOutbound: true);

        Assert.Equal(ProtocolNumber.Tcp, info.Protocol);
        Assert.Equal("10.0.0.5", info.SourceAddress?.ToString());
        Assert.Equal(80, info.DestinationPort);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(13)]
    [InlineData(19)]
    public void Обрезанный_Пакет_Не_Приводит_К_Исключению(int length)
    {
        var packet = PacketFactory.EthernetIpv4Tcp();

        // Парсер обязан переживать обрезку на любой длине и вернуть хоть что-то.
        var info = PacketParser.Parse(packet, 0, length, isOutbound: true);

        Assert.Equal(PacketInfo.Empty.Protocol, info.Protocol);
    }

    [Fact]
    public void Пустой_И_Некорректный_Ввод_Не_Приводит_К_Исключению()
    {
        Assert.Equal(ProtocolNumber.Other, PacketParser.Parse(ReadOnlySpan<byte>.Empty, 0, 0, true).Protocol);

        // offset + length за пределами буфера
        var packet = PacketFactory.EthernetIpv4Tcp();
        Assert.Equal(ProtocolNumber.Other, PacketParser.Parse(packet, 0, packet.Length + 100, true).Protocol);

        // мусор вместо заголовков
        Assert.Equal(ProtocolNumber.Other, PacketParser.Parse(new byte[64], 0, 64, true).Protocol);
    }

    [Fact]
    public void Случайный_Поток_Байтов_Никогда_Не_Бросает()
    {
        var random = new Random(20240610);

        for (int i = 0; i < 3000; i++)
        {
            var buffer = new byte[random.Next(0, 200)];
            random.NextBytes(buffer);

            // Ни одно утверждение: важно лишь отсутствие исключения.
            _ = PacketParser.Parse(buffer, 0, buffer.Length, isOutbound: random.Next(2) == 0);
        }
    }
}