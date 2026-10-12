using System.Net;
using System.Net.Sockets;
using System.Text.Json.Serialization;
using NetGuard.Core.Protocols;

namespace NetGuard.Core.Rules;

/// <summary>Действие правила.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum RuleAction
{
    Allow = 0,
    Deny = 1,
}

/// <summary>Направление, к которому применяется правило.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum RuleDirection
{
    Any = 0,
    Outbound = 1,
    Inbound = 2,
}

/// <summary>
/// Правило списка доступа (ACL).
///
/// Совпадение проверяется по всем заданным полям: незаданное поле считается
/// «любой величиной». Условия соединяются по И. Первое совпавшее правило
/// определяет решение (см. <see cref="RuleSet.Evaluate"/>).
/// </summary>
public sealed class Rule
{
    /// <summary>Идентификатор правила. 0 присваивается автоматически при загрузке.</summary>
    public int Id { get; set; }

    /// <summary>Человекочитаемое имя — попадает в журнал и веб-интерфейс.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Действие при совпадении.</summary>
    public RuleAction Action { get; set; } = RuleAction.Deny;

    /// <summary>
    /// Приоритет: чем меньше значение, тем раньше проверяется правило.
    /// При загрузке конфигурации значения перенумеровываются по порядку,
    /// поэтому вручную задавать их не требуется.
    /// </summary>
    public int Priority { get; set; }

    /// <summary>Правило включено. Выключенные правила пропускаются при проверке.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Протокол: Any / Tcp / Udp / Icmp / IcmpV6.</summary>
    public string Protocol { get; set; } = "Any";

    /// <summary>Направление трафика.</summary>
    public RuleDirection Direction { get; set; } = RuleDirection.Any;

    /// <summary>Адрес источника в CIDR-нотации либо пустая строка — любой.</summary>
    public string SourceAddress { get; set; } = string.Empty;

    /// <summary>Адрес получателя в CIDR-нотации либо пустая строка — любой.</summary>
    public string DestinationAddress { get; set; } = string.Empty;

    /// <summary>Порт источника: "80", "1024-65535", "any".</summary>
    public string SourcePort { get; set; } = "any";

    /// <summary>Порт получателя: "443", "any".</summary>
    public string DestinationPort { get; set; } = "any";

    /// <summary>Записывать ли в журнал пакеты, подошедшие под это правило.</summary>
    public bool Log { get; set; } = true;

    /// <summary>
    /// Счётчик пакетов, подошедших под правило. Заполняется движком
    /// из потока обработки пакетов, поэтому хранится в поле и обновляется
    /// через <see cref="Interlocked"/> (свойство передать в ref нельзя).
    /// </summary>
    public long HitCount
    {
        get => Interlocked.Read(ref _hitCount);
        set => Interlocked.Exchange(ref _hitCount, value);
    }

    /// <summary>Счётчик байт, подошедших под правило.</summary>
    public long HitBytes
    {
        get => Interlocked.Read(ref _hitBytes);
        set => Interlocked.Exchange(ref _hitBytes, value);
    }

    private long _hitCount;
    private long _hitBytes;

    /// <summary>Увеличивает счётчики совпадений. Потокобезопасно.</summary>
    internal void AddHit(int packetLength)
    {
        Interlocked.Increment(ref _hitCount);
        Interlocked.Add(ref _hitBytes, packetLength);
    }

    // ---- подготовленные к сравнению представления ----

    [JsonIgnore]
    internal ProtocolNumber? ParsedProtocol { get; private set; }

    [JsonIgnore]
    internal CidrBlock? SourceBlock { get; private set; }

    [JsonIgnore]
    internal CidrBlock? DestinationBlock { get; private set; }

    [JsonIgnore]
    internal CompositePortSet? SourcePorts { get; private set; }

    [JsonIgnore]
    internal CompositePortSet? DestinationPorts { get; private set; }

    [JsonIgnore]
    internal string? ParseError { get; private set; }

    /// <summary>
    /// Разбирает строковые поля и строит маски сравнения.
    /// Возвращает false, если в правиле ошибка (она попадёт в отчёт о загрузке).
    /// </summary>
    public bool TryPrepare(out string? error)
    {
        error = null;

        ParsedProtocol = Protocol.Trim().ToLowerInvariant() switch
        {
            "" or "any" or "*" => null,
            "tcp" => ProtocolNumber.Tcp,
            "udp" => ProtocolNumber.Udp,
            "icmp" => ProtocolNumber.Icmp,
            "icmpv6" => ProtocolNumber.IcmpV6,
            _ => ProtocolNumber.Other,
        };

        if (ParsedProtocol == ProtocolNumber.Other)
        {
            error = $"неизвестный протокол «{Protocol}» (допустимо: Any, Tcp, Udp, Icmp, IcmpV6)";
            return false;
        }

        if (!string.IsNullOrWhiteSpace(SourceAddress))
        {
            if (!CidrBlock.TryParse(SourceAddress, out var src) || src is null)
            {
                error = $"неверный адрес источника «{SourceAddress}»";
                return false;
            }

            SourceBlock = src;
        }

        if (!string.IsNullOrWhiteSpace(DestinationAddress))
        {
            if (!CidrBlock.TryParse(DestinationAddress, out var dst) || dst is null)
            {
                error = $"неверный адрес получателя «{DestinationAddress}»";
                return false;
            }

            DestinationBlock = dst;
        }

        if (!string.IsNullOrWhiteSpace(SourcePort) && SourcePort.Trim() != "any")
        {
            if (!CompositePortSet.TryParse(SourcePort, out var sp) || sp is null)
            {
                error = $"неверный порт источника «{SourcePort}»";
                return false;
            }

            SourcePorts = sp;
        }

        if (!string.IsNullOrWhiteSpace(DestinationPort) && DestinationPort.Trim() != "any")
        {
            if (!CompositePortSet.TryParse(DestinationPort, out var dp) || dp is null)
            {
                error = $"неверный порт получателя «{DestinationPort}»";
                return false;
            }

            DestinationPorts = dp;
        }

        ParseError = null;
        return true;
    }

    /// <summary>
    /// Проверяет, подходит ли пакет под правило.
    ///
    /// Порты сравниваются, только когда у пакета они есть и разобраны:
    /// у ICMP и у фрагментов портов нет, и правило вида «TCP 80» не должно
    /// случайно совпасть с ICMP-пакетом.
    /// </summary>
    public bool Matches(in PacketInfo packet, TrafficDirection direction)
    {
        if (!Enabled)
            return false;

        if (Direction != RuleDirection.Any && !MatchesDirection(Direction, direction))
            return false;

        if (ParsedProtocol is { } expected && expected != packet.Protocol)
            return false;

        if (SourceBlock is { } src && !src.Contains(packet.SourceAddress))
            return false;

        if (DestinationBlock is { } dst && !dst.Contains(packet.DestinationAddress))
            return false;

        if (SourcePorts is { } sourcePorts || DestinationPorts is { } destinationPorts)
        {
            if (!packet.HasPorts)
                return false;

            if (SourcePorts is { } s && !s.Contains(packet.SourcePort))
                return false;

            if (DestinationPorts is { } d && !d.Contains(packet.DestinationPort))
                return false;
        }

        return true;
    }

    private static bool MatchesDirection(RuleDirection rule, TrafficDirection actual)
    {
        if (actual == TrafficDirection.Unknown)
            return true;

        return rule switch
        {
            RuleDirection.Outbound => actual == TrafficDirection.Outbound,
            RuleDirection.Inbound => actual == TrafficDirection.Inbound,
            _ => true,
        };
    }

    /// <summary>Копия правила — нужна для редактирования через веб-интерфейс.</summary>
    public Rule Clone() => new()
    {
        Id = Id,
        Name = Name,
        Action = Action,
        Priority = Priority,
        Enabled = Enabled,
        Protocol = Protocol,
        Direction = Direction,
        SourceAddress = SourceAddress,
        DestinationAddress = DestinationAddress,
        SourcePort = SourcePort,
        DestinationPort = DestinationPort,
        Log = Log,
    };

    /// <summary>Краткое описание для журнала: "DENY tcp 0.0.0.0/0:any -> 10.0.0.5/32:443".</summary>
    public string Describe()
    {
        string proto = string.IsNullOrWhiteSpace(Protocol) ? "any" : Protocol.ToLowerInvariant();
        string src = string.IsNullOrWhiteSpace(SourceAddress) ? "any" : SourceAddress;
        string dst = string.IsNullOrWhiteSpace(DestinationAddress) ? "any" : DestinationAddress;
        string sport = string.IsNullOrWhiteSpace(SourcePort) ? "any" : SourcePort;
        string dport = string.IsNullOrWhiteSpace(DestinationPort) ? "any" : DestinationPort;

        return $"{proto} {src}:{sport} -> {dst}:{dport}";
    }
}