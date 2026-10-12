using System.Net;
using NetGuard.Core.Protocols;
using NetGuard.Core.Rules;
using Xunit;

namespace NetGuard.Tests;

/// <summary>
/// Проверка сопоставления адресов, портов и правил
/// (п. 3.1 ТЗ № 3, 4, 5, 6).
/// </summary>
public class RuleTests
{
    private static PacketInfo TcpPacket(
        string src = "10.0.0.1", string dst = "93.184.216.34",
        ushort sport = 51515, ushort dport = 443) =>
        PacketParser.Parse(
            PacketFactory.EthernetIpv4Tcp(src, dst, sport, dport), 0,
            PacketFactory.EthernetIpv4Tcp(src, dst, sport, dport).Length,
            isOutbound: true);

    // ---------------- CIDR ----------------

    [Theory]
    [InlineData("10.0.0.0/8", "10.1.2.3", true)]
    [InlineData("10.0.0.0/8", "11.1.2.3", false)]
    [InlineData("192.168.1.0/24", "192.168.1.255", true)]
    [InlineData("192.168.1.0/24", "192.168.2.0", false)]
    [InlineData("0.0.0.0/0", "8.8.8.8", true)]
    [InlineData("172.16.0.0/12", "172.31.255.255", true)]
    [InlineData("172.16.0.0/12", "172.32.0.0", false)]
    public void Cidr_Содержит_Ipv4(string cidr, string address, bool expected)
    {
        Assert.True(CidrBlock.TryParse(cidr, out var block));
        Assert.Equal(expected, block!.Contains(IPAddress.Parse(address)));
    }

    [Theory]
    [InlineData("2001:db8::/32", "2001:db8:1:2::1", true)]
    [InlineData("2001:db8::/32", "2001:db9::1", false)]
    [InlineData("::/0", "fe80::1", true)]
    public void Cidr_Содержит_Ipv6(string cidr, string address, bool expected)
    {
        Assert.True(CidrBlock.TryParse(cidr, out var block));
        Assert.Equal(expected, block!.Contains(IPAddress.Parse(address)));
    }

    [Fact]
    public void Cidr_Без_Префикса_Совпадает_Только_С_Точным_Адресом()
    {
        Assert.True(CidrBlock.TryParse("10.0.0.1", out var block));
        Assert.True(block!.Contains(IPAddress.Parse("10.0.0.1")));
        Assert.False(block.Contains(IPAddress.Parse("10.0.0.2")));
    }

    [Fact]
    public void Cidr_Не_Смешивает_Ipv4_И_Ipv6()
    {
        Assert.True(CidrBlock.TryParse("10.0.0.0/8", out var v4));
        Assert.False(v4!.Contains(IPAddress.Parse("2001:db8::1")));
    }

    [Fact]
    public void Ipv4_Mapped_Ipv6_Совпадает_Ipv4_Подсетью()
    {
        // ::ffff:10.0.0.1 должен распознаваться как 10.0.0.1,
        // иначе правило для внутренней сети не сработает.
        Assert.True(CidrBlock.TryParse("10.0.0.0/8", out var block));
        Assert.True(block!.Contains(IPAddress.Parse("::ffff:10.0.0.1")));
    }

    [Theory]
    [InlineData("10.0.0.0/33")]
    [InlineData("не адрес")]
    [InlineData("10.0.0.0/abc")]
    public void Некорректный_Cidr_Отвергается(string text) =>
        Assert.False(CidrBlock.TryParse(text, out _));

    // ---------------- порты ----------------

    [Theory]
    [InlineData("80", 80, true)]
    [InlineData("80", 81, false)]
    [InlineData("1024-65535", 5000, true)]
    [InlineData("1024-65535", 80, false)]
    [InlineData("any", 12345, true)]
    [InlineData("1024-", 50000, true)]
    [InlineData("1024-", 80, false)]
    public void Диапазон_Портов_Содержит(string spec, int port, bool expected)
    {
        Assert.True(PortRange.TryParse(spec, out var range));
        Assert.Equal(expected, range.Contains((ushort)port));
    }

    [Fact]
    public void Набор_Портов_С_пирами_Разбирается()
    {
        Assert.True(CompositePortSet.TryParse("80,443,8000-8080", out var set));
        Assert.True(set!.Contains(80));
        Assert.True(set.Contains(443));
        Assert.True(set.Contains(8000));
        Assert.True(set.Contains(8080));
        Assert.False(set.Contains(8081));
        Assert.False(set.Contains(22));
    }

    [Fact]
    public void Неверный_Порт_Даёт_Ошибку_В_Правиле()
    {
        var rule = new Rule { DestinationPort = "не порт" };

        Assert.False(rule.TryPrepare(out var error));
        Assert.Contains("порт", error, StringComparison.OrdinalIgnoreCase);
    }

    // ---------------- правила ----------------

    [Fact]
    public void Правило_По_Порту_Совпадает()
    {
        var rule = new Rule { Protocol = "Tcp", DestinationPort = "443" };
        Assert.True(rule.TryPrepare(out _));

        Assert.True(rule.Matches(TcpPacket(dport: 443), TrafficDirection.Outbound));
        Assert.False(rule.Matches(TcpPacket(dport: 80), TrafficDirection.Outbound));
    }

    [Fact]
    public void Правило_По_Направлению_Разделяет_Трафик()
    {
        var inbound = new Rule { Direction = RuleDirection.Inbound, Protocol = "Tcp" };
        Assert.True(inbound.TryPrepare(out _));

        Assert.True(inbound.Matches(TcpPacket(), TrafficDirection.Inbound));
        Assert.False(inbound.Matches(TcpPacket(), TrafficDirection.Outbound));
    }

    [Fact]
    public void Правило_С_Портом_Не_Совпадает_С_Icmp()
    {
        // У ICMP портов нет: правило «TCP/443» не должно срабатывать на ping.
        var rule = new Rule { Protocol = "Tcp", DestinationPort = "443" };
        Assert.True(rule.TryPrepare(out _));

        var icmp = PacketParser.Parse(
            PacketFactory.EthernetIpv4Icmp(), 0,
            PacketFactory.EthernetIpv4Icmp().Length, isOutbound: true);

        Assert.False(rule.Matches(icmp, TrafficDirection.Outbound));
    }

    [Fact]
    public void Правило_Без_Протокола_Ловит_Любой()
    {
        var rule = new Rule { DestinationPort = "any" };
        Assert.True(rule.TryPrepare(out _));

        var icmp = PacketParser.Parse(
            PacketFactory.EthernetIpv4Icmp(), 0,
            PacketFactory.EthernetIpv4Icmp().Length, isOutbound: true);

        Assert.True(rule.Matches(icmp, TrafficDirection.Outbound));
    }

    [Fact]
    public void Выключенное_Правило_Не_Совпадает()
    {
        var rule = new Rule { Enabled = false, Protocol = "Tcp", DestinationPort = "443" };
        Assert.True(rule.TryPrepare(out _));

        Assert.False(rule.Matches(TcpPacket(dport: 443), TrafficDirection.Outbound));
    }

    // ---------------- список правил ----------------

    [Fact]
    public void Приоритет_Решает_Победителя()
    {
        var rules = new List<Rule>
        {
            new() { Name = "запретить 443", Action = RuleAction.Deny, Protocol = "Tcp", DestinationPort = "443" },
            new() { Name = "разрешить всё", Action = RuleAction.Allow },
        };

        var set = RuleSet.Create(rules, RuleAction.Deny, out var errors);
        Assert.Empty(errors);

        var decision = set.Evaluate(TcpPacket(dport: 443), TrafficDirection.Outbound);

        Assert.Equal(RuleAction.Deny, decision.Action);
        Assert.Equal("запретить 443", decision.MatchedRule?.Name);
    }

    [Fact]
    public void Порядок_Правил_Меняет_Результат()
    {
        var rules = new List<Rule>
        {
            new() { Name = "разрешить всё", Action = RuleAction.Allow },
            new() { Name = "запретить 443", Action = RuleAction.Deny, Protocol = "Tcp", DestinationPort = "443" },
        };

        var set = RuleSet.Create(rules, RuleAction.Deny, out _);

        var decision = set.Evaluate(TcpPacket(dport: 443), TrafficDirection.Outbound);

        Assert.Equal(RuleAction.Allow, decision.Action);
    }

    [Fact]
    public void Без_Совпадений_Применяется_Политика_По_Умолчанию()
    {
        var set = RuleSet.Create([], RuleAction.Deny, out _);

        var decision = set.Evaluate(TcpPacket(), TrafficDirection.Outbound);

        Assert.Equal(RuleAction.Deny, decision.Action);
        Assert.Null(decision.MatchedRule);
        Assert.Contains("политика по умолчанию", decision.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Счётчики_Правила_Растут()
    {
        var rule = new Rule { Name = "счётчик", Action = RuleAction.Deny, Protocol = "Tcp", DestinationPort = "443" };
        var set = RuleSet.Create([rule], RuleAction.Allow, out _);

        for (int i = 0; i < 5; i++)
        {
            var decision = set.Evaluate(TcpPacket(dport: 443), TrafficDirection.Outbound);
            set.RecordHit(decision.MatchedRule, 100);
        }

        Assert.Equal(5, rule.HitCount);
        Assert.Equal(500, rule.HitBytes);
    }

    [Fact]
    public void Некорректное_Правило_Попадает_В_Список_Ошибок()
    {
        var rules = new List<Rule>
        {
            new() { Name = "хорошее", Action = RuleAction.Allow, Protocol = "Tcp", DestinationPort = "443" },
            new() { Name = "плохое", Protocol = "FTP" },
        };

        var set = RuleSet.Create(rules, RuleAction.Deny, out var errors);

        Assert.Single(errors);
        Assert.Contains("плохое", errors[0], StringComparison.OrdinalIgnoreCase);

        // Битое правило отброшено, хорошее работает.
        Assert.Equal(1, set.Count);
        Assert.Equal(RuleAction.Allow, set.Evaluate(TcpPacket(dport: 443), TrafficDirection.Outbound).Action);
    }

    [Fact]
    public void Правила_Получают_Последовательные_Идентификаторы_И_Приоритеты()
    {
        var rules = new List<Rule>
        {
            new() { Name = "первое" },
            new() { Name = "второе" },
            new() { Name = "третье" },
        };

        var set = RuleSet.Create(rules, RuleAction.Deny, out _);

        Assert.Equal([1, 2, 3], set.Rules.Select(r => r.Id));
        Assert.Equal([1, 2, 3], set.Rules.Select(r => r.Priority));
        Assert.Equal("первое", set.Rules[0].Name);
    }

    // ---------------- поиск пересечений ----------------

    [Theory]
    [InlineData("10.0.0.0/8", "10.1.0.0/16", true)]
    [InlineData("10.0.0.0/8", "11.0.0.0/16", false)]
    [InlineData("192.168.1.0/24", "192.168.1.128/25", true)]
    [InlineData("192.168.1.0/24", "192.168.2.0/24", false)]
    [InlineData("0.0.0.0/0", "10.0.0.0/8", true)]
    public void Подсети_Пересекаются_По_Общему_Префиксу(string a, string b, bool expected)
    {
        Assert.True(CidrBlock.TryParse(a, out var x));
        Assert.True(CidrBlock.TryParse(b, out var y));

        Assert.Equal(expected, x!.Intersects(y));
        Assert.Equal(expected, y!.Intersects(x));
    }

    [Fact]
    public void Наборы_Портов_Пересекаются()
    {
        Assert.True(CompositePortSet.MayIntersect(null, null));
        Assert.True(CompositePortSet.MayIntersect(
            CompositePortSet.TryParse("80", out var a) ? a : null,
            CompositePortSet.TryParse("8000-9000", out var b) ? b : null) == false);
        Assert.True(CompositePortSet.MayIntersect(
            CompositePortSet.TryParse("80,1000-2000", out var c) ? c : null,
            CompositePortSet.TryParse("1500", out var d) ? d : null));
    }

    [Fact]
    public void Пересечение_Правил_Предупреждает_Только_О_Разных_Действиях()
    {
        // Allow/Allow по одному порту: порядок не важен — предупреждения быть не должно.
        var same = RuleSet.Create(
        [
            new Rule { Name = "a", Action = RuleAction.Allow, Protocol = "Tcp", DestinationPort = "443" },
            new Rule { Name = "b", Action = RuleAction.Allow, Protocol = "Tcp", DestinationPort = "443" },
        ], RuleAction.Deny, out _);

        Assert.Empty(same.Analyse());
    }

    [Fact]
    public void Allow_И_Deny_На_Один_Порт_Дают_Предупреждение()
    {
        var conflict = RuleSet.Create(
        [
            new Rule { Name = "запретить", Action = RuleAction.Deny, Protocol = "Tcp", DestinationPort = "443" },
            new Rule { Name = "разрешить", Action = RuleAction.Allow, Protocol = "Tcp", DestinationPort = "443" },
        ], RuleAction.Deny, out _);

        Assert.Single(conflict.Analyse());
    }

    [Fact]
    public void Разные_Порты_Не_Считаются_Конфликтом()
    {
        var noConflict = RuleSet.Create(
        [
            new Rule { Name = "запретить 80", Action = RuleAction.Deny, Protocol = "Tcp", DestinationPort = "80" },
            new Rule { Name = "разрешить 443", Action = RuleAction.Allow, Protocol = "Tcp", DestinationPort = "443" },
        ], RuleAction.Deny, out _);

        Assert.Empty(noConflict.Analyse());
    }

    [Fact]
    public void Разные_Подсети_Не_Считаются_Конфликтом()
    {
        var noConflict = RuleSet.Create(
        [
            new Rule { Name = "внешние", Action = RuleAction.Deny, DestinationAddress = "93.184.0.0/16" },
            new Rule { Name = "внутренние", Action = RuleAction.Allow, DestinationAddress = "10.0.0.0/8" },
        ], RuleAction.Deny, out _);

        Assert.Empty(noConflict.Analyse());
    }
}