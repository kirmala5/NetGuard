using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using NetGuard.Core.Protocols;
using NetGuard.Core.Rules;

namespace NetGuard.Core.Logging;

/// <summary>
/// Запись журнала (п. 3.1 ТЗ № 7): время, адреса, порты, протокол,
/// направление, решение и сработавшее правило.
/// </summary>
public sealed record FirewallLogEntry
{
    public required DateTimeOffset Timestamp { get; init; }
    public required TrafficDirection Direction { get; init; }
    public required RuleAction Action { get; init; }
    public required string Protocol { get; init; }
    public string? SourceAddress { get; init; }
    public int SourcePort { get; init; }
    public string? DestinationAddress { get; init; }
    public int DestinationPort { get; init; }
    public int PacketLength { get; init; }
    public int? RuleId { get; init; }
    public string? RuleName { get; init; }
    public string Reason { get; init; } = string.Empty;
    public bool IsFragment { get; init; }

    /// <summary>Строка в формате CSV без обрамляющих кавычек.</summary>
    public string ToCsv()
    {
        return string.Join(',',
            Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff zzz", CultureInfo.InvariantCulture),
            Direction.ToString(),
            Protocol,
            SourceAddress ?? "-",
            SourcePort.ToString(CultureInfo.InvariantCulture),
            DestinationAddress ?? "-",
            DestinationPort.ToString(CultureInfo.InvariantCulture),
            PacketLength.ToString(CultureInfo.InvariantCulture),
            Action.ToString().ToUpperInvariant(),
            RuleId?.ToString(CultureInfo.InvariantCulture) ?? "-",
            Escape(RuleName ?? "-"),
            IsFragment ? "fragment" : "-",
            Escape(Reason));
    }

    /// <summary>Человекочитаемая строка для консоли.</summary>
    public string ToDisplayString() =>
        $"{Timestamp:HH:mm:ss.fff} {Direction,-8} {Protocol,-6} " +
        $"{SourceAddress}:{SourcePort} -> {DestinationAddress}:{DestinationPort} " +
        $"[{Action.ToString().ToUpperInvariant()}] {Reason}";

    /// <summary>
    /// Экранирование для CSV: запятая, кавычка и перевод строки внутри
    /// значения иначе ломают разбор файла.
    /// </summary>
    private const string CsvSpecialChars = ",\"\r\n";

    private static string Escape(string value)
    {
        if (value.AsSpan().IndexOfAny(CsvSpecialChars.AsSpan()) < 0)
            return value;

        return '"' + value.Replace("\"", "\"\"") + '"';
    }

    public static FirewallLogEntry FromPacket(
        in PacketInfo packet,
        TrafficDirection direction,
        RuleAction action,
        Rule? rule,
        int packetLength) =>
        new()
        {
            Timestamp = DateTimeOffset.Now,
            Direction = direction,
            Action = action,
            Protocol = packet.ProtocolName,
            SourceAddress = packet.SourceAddress?.ToString(),
            SourcePort = packet.SourcePort,
            DestinationAddress = packet.DestinationAddress?.ToString(),
            DestinationPort = packet.DestinationPort,
            PacketLength = packetLength,
            RuleId = rule?.Id,
            RuleName = rule?.Name,
            Reason = rule is null ? "политика по умолчанию" : $"правило #{rule.Id} «{rule.Name}»",
            IsFragment = packet.IsFragment,
        };
}

/// <summary>Приёмник событий журнала.</summary>
public interface IEventSink
{
    void Write(FirewallLogEntry entry);
}

/// <summary>Кольцевой буфер в памяти: последние события для CLI и веб-интерфейса.</summary>
public sealed class MemoryEventSink : IEventSink
{
    private readonly ConcurrentQueue<FirewallLogEntry> _entries = new();
    private readonly int _capacity;
    private long _written;
    private long _dropped;

    public MemoryEventSink(int capacity)
    {
        _capacity = Math.Max(0, capacity);
    }

    public void Write(FirewallLogEntry entry)
    {
        if (_capacity == 0)
            return;

        _entries.Enqueue(entry);
        Interlocked.Increment(ref _written);

        while (_entries.Count > _capacity && _entries.TryDequeue(out _))
            Interlocked.Increment(ref _dropped);
    }

    /// <summary>Последние <paramref name="count"/> событий, от новых к старым.</summary>
    public IReadOnlyList<FirewallLogEntry> Tail(int count)
    {
        if (count <= 0)
            return [];

        var all = _entries.ToArray();
        if (all.Length <= count)
            return all;

        var result = new FirewallLogEntry[count];
        Array.Copy(all, all.Length - count, result, 0, count);

        // Для чтения в интерфейсе удобнее newest-first.
        Array.Reverse(result);
        return result;
    }

    public long TotalWritten => Interlocked.Read(ref _written);
    public long TotalDropped => Interlocked.Read(ref _dropped);
}

/// <summary>
/// Запись событий в CSV-файл (п. 3.1 ТЗ № 7).
///
/// Файл выбран вместо JSONL сознательно: CSV без усилий открывается в
/// Excel и в любом просмотрщике, а для курсовой работы это важнее
/// строгой типизации полей.
/// </summary>
public sealed class CsvEventSink : IEventSink, IDisposable
{
    private static readonly string Header =
        "timestamp,direction,protocol,src_ip,src_port,dst_ip,dst_port,length,action,rule_id,rule_name,fragment,reason";

    private readonly object _gate = new();
    private readonly string _directory;
    private readonly string _fileNameTemplate;
    private StreamWriter? _writer;
    private string? _currentPath;
    private DateOnly _currentDay;
    private long _written;
    private long _failed;

    public CsvEventSink(string directory, string fileNameTemplate)
    {
        _directory = string.IsNullOrWhiteSpace(directory) ? Directory.GetCurrentDirectory() : directory;
        _fileNameTemplate = string.IsNullOrWhiteSpace(fileNameTemplate)
            ? "firewall-{date}.csv"
            : fileNameTemplate;
    }

    /// <summary>Путь текущего файла журнала (null, пока файл не создан).</summary>
    public string? CurrentFile => _currentPath;

    public long TotalWritten => Interlocked.Read(ref _written);
    public long TotalFailed => Interlocked.Read(ref _failed);

    public void Write(FirewallLogEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        try
        {
            lock (_gate)
            {
                EnsureWriter(entry.Timestamp);
                _writer?.WriteLine(entry.ToCsv());
            }

            Interlocked.Increment(ref _written);
        }
        catch
        {
            // Сбой записи в журнал не должен останавливать фильтрацию:
            // это диагностическая, а не функциональная подсистема.
            Interlocked.Increment(ref _failed);
        }
    }

    private void EnsureWriter(DateTimeOffset timestamp)
    {
        var day = DateOnly.FromDateTime(timestamp.LocalDateTime);

        // Новый день — новый файл: журнал остаётся читаемым по суткам.
        if (_writer is not null && day == _currentDay)
            return;

        _writer?.Flush();
        _writer?.Dispose();
        _writer = null;
        _currentPath = null;

        Directory.CreateDirectory(_directory);

        string fileName = _fileNameTemplate.Replace("{date}", day.ToString("yyyy-MM-dd"));
        string path = Path.Combine(_directory, fileName);

        bool exists = File.Exists(path);

        var writer = new StreamWriter(
            new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

        // Заголовок нужен только в новом файле.
        if (!exists || new FileInfo(path).Length == 0)
            writer.WriteLine(Header);

        _writer = writer;
        _currentPath = path;
        _currentDay = day;
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _writer?.Flush();
            _writer?.Dispose();
            _writer = null;
            _currentPath = null;
        }
    }
}

/// <summary>Печать событий в консоль — для режима `--verbose`.</summary>
public sealed class ConsoleEventSink(Action<string> write) : IEventSink
{
    private readonly Action<string> _write = write ?? Console.WriteLine;

    public void Write(FirewallLogEntry entry) => _write(entry.ToDisplayString());
}

/// <summary>Приёмник, который ничего не делает.</summary>
public sealed class NullEventSink : IEventSink
{
    public static NullEventSink Instance { get; } = new();

    public void Write(FirewallLogEntry entry) { }
}