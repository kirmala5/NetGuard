using System.Collections.Concurrent;
using NetGuard.Core.Protocols;

namespace NetGuard.Core.Statistics;

/// <summary>
/// Счётчики трафика. Обновляются из потока обработки пакетов,
/// поэтому все счётчики — атомарные, а выборка — lock-free.
/// </summary>
public sealed class TrafficStatistics
{
    private long _total;
    private long _allowed;
    private long _denied;
    private long _allowedBytes;
    private long _deniedBytes;
    private long _unparsed;
    private long _parseFailures;

    private readonly long[] _byProtocol = new long[6];
    private readonly long[] _byDirection = new long[2];

    private readonly ConcurrentDictionary<string, long> _topBlocked = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, long> _topAllowed = new(StringComparer.Ordinal);

    /// <summary>Пакетов всего.</summary>
    public long Total => Interlocked.Read(ref _total);
    public long Allowed => Interlocked.Read(ref _allowed);
    public long Denied => Interlocked.Read(ref _denied);
    public long AllowedBytes => Interlocked.Read(ref _allowedBytes);
    public long DeniedBytes => Interlocked.Read(ref _deniedBytes);

    /// <summary>Пакеты, которые не удалось разобрать (считаются как разрешённые).</summary>
    public long Unparsed => Interlocked.Read(ref _unparsed);

    /// <summary>Ошибки разбора (исключения в парсере).</summary>
    public long ParseFailures => Interlocked.Read(ref _parseFailures);

    public long PacketsTo(ProtocolNumber protocol) =>
        Interlocked.Read(ref _byProtocol[(int)ProtocolNumberIndex(protocol)]);

    public long Outbound => Interlocked.Read(ref _byDirection[0]);
    public long Inbound => Interlocked.Read(ref _byDirection[1]);

    public void RecordPacket(in PacketInfo packet, TrafficDirection direction)
    {
        Interlocked.Increment(ref _total);
        Interlocked.Increment(ref _byProtocol[(int)ProtocolNumberIndex(packet.Protocol)]);

        if (direction == TrafficDirection.Outbound)
            Interlocked.Increment(ref _byDirection[0]);
        else if (direction == TrafficDirection.Inbound)
            Interlocked.Increment(ref _byDirection[1]);
    }

    public void RecordDecision(bool allowed, int length, in PacketInfo packet)
    {
        if (allowed)
        {
            Interlocked.Increment(ref _allowed);
            Interlocked.Add(ref _allowedBytes, length);
            Track(_topAllowed, packet);
        }
        else
        {
            Interlocked.Increment(ref _denied);
            Interlocked.Add(ref _deniedBytes, length);
            Track(_topBlocked, packet);
        }
    }

    public void RecordUnparsed(int length)
    {
        Interlocked.Increment(ref _unparsed);
        Interlocked.Increment(ref _allowed);
        Interlocked.Add(ref _allowedBytes, length);
    }

    public void RecordParseFailure() => Interlocked.Increment(ref _parseFailures);

    private static void Track(ConcurrentDictionary<string, long> map, in PacketInfo packet)
    {
        string? key = packet.DestinationAddress?.ToString();

        // Входящий трафик интереснее видеть по отправителю, исходящий — по получателю.
        if (packet.DestinationAddress is null)
            key = packet.SourceAddress?.ToString();
        else if (packet.SourceAddress is not null &&
                 System.Net.IPAddress.IsLoopback(packet.SourceAddress))
        {
            key = packet.DestinationAddress.ToString();
        }

        if (key is null)
            return;

        map.AddOrUpdate(key, 1, static (_, current) => current + 1);
    }

    /// <summary>Снимок статистики для CLI и веб-интерфейса.</summary>
    public StatisticsSnapshot Snapshot(int topLimit = 10) => new()
    {
        CapturedAt = DateTimeOffset.Now,
        Total = Total,
        Allowed = Allowed,
        Denied = Denied,
        AllowedBytes = AllowedBytes,
        DeniedBytes = DeniedBytes,
        Unparsed = Unparsed,
        ParseFailures = ParseFailures,
        Tcp = PacketsTo(ProtocolNumber.Tcp),
        Udp = PacketsTo(ProtocolNumber.Udp),
        Icmp = PacketsTo(ProtocolNumber.Icmp),
        IcmpV6 = PacketsTo(ProtocolNumber.IcmpV6),
        Outbound = Outbound,
        Inbound = Inbound,
        TopBlocked = Top(_topBlocked, topLimit),
        TopAllowed = Top(_topAllowed, topLimit),
    };

    private static IReadOnlyList<TopCounter> Top(ConcurrentDictionary<string, long> map, int limit) =>
        map.OrderByDescending(kv => kv.Value)
           .Take(limit)
           .Select(kv => new TopCounter(kv.Key, kv.Value))
           .ToArray();

    private static int ProtocolNumberIndex(ProtocolNumber protocol) => protocol switch
    {
        ProtocolNumber.Tcp => 1,
        ProtocolNumber.Udp => 2,
        ProtocolNumber.Icmp => 3,
        ProtocolNumber.IcmpV6 => 4,
        _ => 5,
    };
}

public sealed record TopCounter(string Address, long Packets);

/// <summary>Неизменяемый снимок счётчиков.</summary>
public sealed record StatisticsSnapshot
{
    public required DateTimeOffset CapturedAt { get; init; }
    public long Total { get; init; }
    public long Allowed { get; init; }
    public long Denied { get; init; }
    public long AllowedBytes { get; init; }
    public long DeniedBytes { get; init; }
    public long Unparsed { get; init; }
    public long ParseFailures { get; init; }
    public long Tcp { get; init; }
    public long Udp { get; init; }
    public long Icmp { get; init; }
    public long IcmpV6 { get; init; }
    public long Outbound { get; init; }
    public long Inbound { get; init; }
    public IReadOnlyList<TopCounter> TopBlocked { get; init; } = [];
    public IReadOnlyList<TopCounter> TopAllowed { get; init; } = [];
}