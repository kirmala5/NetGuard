using NetGuard.Core.Configuration;
using NetGuard.Core.Logging;
using NetGuard.Core.Protocols;
using NetGuard.Core.Rules;
using NetGuard.Core.Statistics;
using Xunit;

namespace NetGuard.Tests;

/// <summary>
/// Проверка загрузки конфигурации (п. 3.1 ТЗ № 8) и журнала (№ 7).
/// </summary>
public class ConfigAndLoggingTests : IDisposable
{
    private readonly string _tempDir = Path.Combine(
        Path.GetTempPath(), "netguard-tests-" + Guid.NewGuid().ToString("N")[..8]);

    public ConfigAndLoggingTests() => Directory.CreateDirectory(_tempDir);

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, recursive: true);
        }
        catch
        {
            // Временный каталог тестов не должен ронять прогон.
        }
    }

    [Fact]
    public void Конфигурация_По_Умолчанию_Сохраняется_И_Читается()
    {
        var path = Path.Combine(_tempDir, "rules.json");
        var config = ConfigLoader.CreateDefault();

        ConfigLoader.Save(config, path);
        Assert.True(File.Exists(path));

        var result = ConfigLoader.Load(path);

        Assert.True(result.Success, string.Join("; ", result.Errors));
        Assert.NotNull(result.RuleSet);
        Assert.Equal(RuleAction.Deny, result.RuleSet!.DefaultAction);
        Assert.Equal(config.Rules.Count, result.RuleSet.Count);
    }

    [Fact]
    public void Правила_Читаются_Из_Json_С_Читаемыми_Именами_Действий()
    {
        string json = """
        {
          "defaultAction": "Allow",
          "capture": { "includeLoopback": true, "queueLength": 1024 },
          "logging":  { "enabled": false, "logAllowed": true },
          "rules": [
            { "name": "разрешить ssh", "action": "Allow", "protocol": "Tcp",
              "destinationPort": "22", "sourceAddress": "192.168.1.0/24" }
          ]
        }
        """;

        var path = Path.Combine(_tempDir, "custom.json");
        File.WriteAllText(path, json);

        var result = ConfigLoader.Load(path);

        Assert.True(result.Success, string.Join("; ", result.Errors));
        Assert.Equal(RuleAction.Allow, result.RuleSet!.DefaultAction);
        Assert.True(result.Config!.Capture.IncludeLoopback);
        Assert.Equal(1024, result.Config.Capture.QueueLength);
        Assert.False(result.Config.Logging.Enabled);
        Assert.Single(result.RuleSet.Rules);
        Assert.Equal("разрешить ssh", result.RuleSet.Rules[0].Name);
    }

    [Fact]
    public void Некорректный_Json_Не_Ломает_Загрузку()
    {
        var path = Path.Combine(_tempDir, "broken.json");
        File.WriteAllText(path, "{ \"rules\": [ { \"name\": ");

        var result = ConfigLoader.Load(path);

        Assert.False(result.Success);
        Assert.Contains(result.Errors, e => e.Contains("JSON", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Отсутствующий_Файл_Сообщает_Об_Ошибке()
    {
        var result = ConfigLoader.Load(Path.Combine(_tempDir, "нет-такого.json"));

        Assert.False(result.Success);
        Assert.Contains(result.Errors, e => e.Contains("не найден", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Некорректное_Правило_Не_Ломает_Остальные()
    {
        string json = """
        {
          "defaultAction": "Deny",
          "rules": [
            { "name": "плохой порт", "action": "Deny", "destinationPort": "не-порт" },
            { "name": "хороший", "action": "Allow", "protocol": "Udp", "destinationPort": "53" }
          ]
        }
        """;

        var path = Path.Combine(_tempDir, "partial.json");
        File.WriteAllText(path, json);

        var result = ConfigLoader.Load(path);

        Assert.False(result.Success);
        Assert.Single(result.Errors);
        Assert.Equal(1, result.RuleSet!.Count);
        Assert.Equal("хороший", result.RuleSet.Rules[0].Name);
    }

    [Fact]
    public void Пустой_Список_Правил_С_Deny_Даёт_Предупреждение()
    {
        string json = """{ "defaultAction": "Deny", "rules": [] }""";

        var path = Path.Combine(_tempDir, "empty.json");
        File.WriteAllText(path, json);

        var result = ConfigLoader.Load(path);

        Assert.Contains(result.Warnings, w => w.Contains("DefaultAction=Deny", StringComparison.Ordinal));
    }

    [Fact]
    public void Комментарии_В_Json_Допустимы()
    {
        string json = """
        {
          // политика по умолчанию
          "defaultAction": "Allow",
          "rules": []
        }
        """;

        var path = Path.Combine(_tempDir, "comments.json");
        File.WriteAllText(path, json);

        Assert.True(ConfigLoader.Load(path).Success);
    }

    // ---------------- журнал ----------------

    [Fact]
    public void Csv_Журнал_Пишет_Заголовок_И_Строки()
    {
        var path = Path.Combine(_tempDir, "log");
        using var sink = new CsvEventSink(path, "firewall-{date}.csv");

        sink.Write(MakeEntry("10.0.0.1", 51515, "93.184.216.34", 443, RuleAction.Deny, "правило #1"));
        sink.Write(MakeEntry("10.0.0.2", 51516, "8.8.8.8", 53, RuleAction.Allow, "правило #2"));
        sink.Dispose();

        var file = Directory.GetFiles(path, "firewall-*.csv").Single();
        var lines = File.ReadAllLines(file);

        Assert.Equal(3, lines.Length);
        Assert.StartsWith("timestamp,direction,protocol", lines[0], StringComparison.Ordinal);
        Assert.Contains("10.0.0.1", lines[1]);
        Assert.Contains("DENY", lines[1]);
        Assert.Contains("ALLOW", lines[2]);
    }

    [Fact]
    public void Csv_Экранирует_Запятые_В_Названии_Правила()
    {
        var path = Path.Combine(_tempDir, "log2");
        using var sink = new CsvEventSink(path, "f.csv");

        sink.Write(MakeEntry("10.0.0.1", 1, "10.0.0.2", 2, RuleAction.Deny, "блок, всё подряд"));
        sink.Dispose();

        var line = File.ReadAllLines(Path.Combine(path, "f.csv"))[1];

        Assert.Contains("\"блок, всё подряд\"", line, StringComparison.Ordinal);
    }

    [Fact]
    public void Недоступный_Каталог_Не_Приводит_К_Исключению()
    {
        // Путь, который невозможно создать: имя файла в середине.
        var sink = new CsvEventSink("\0invalid\0path", "f.csv");

        // Ошибка записи ловится внутри приёмника и не выходит наружу.
        sink.Write(MakeEntry("1.1.1.1", 1, "2.2.2.2", 2, RuleAction.Deny, "тест"));
        sink.Dispose();

        Assert.True(sink.TotalFailed > 0);
    }

    [Fact]
    public void Кольцевой_Буфер_Отдаёт_Последние_События()
    {
        var sink = new MemoryEventSink(capacity: 5);

        for (int i = 1; i <= 20; i++)
            sink.Write(MakeEntry($"10.0.0.{i % 250 + 1}", i, "10.0.1.1", 80, RuleAction.Allow, $"r{i}"));

        var tail = sink.Tail(3);

        Assert.Equal(3, tail.Count);
        Assert.Equal(20, sink.TotalWritten);
        Assert.True(sink.TotalDropped > 0);

        // Tail отдаёт события от новых к старым, поэтому первым идёт последнее.
        Assert.Equal(20, tail[0].SourcePort);
        Assert.Equal(19, tail[1].SourcePort);
    }

    // ---------------- статистика ----------------

    [Fact]
    public void Статистика_Считает_Разрешённые_И_Заблокированные()
    {
        var stats = new TrafficStatistics();
        var packet = PacketInfo.Empty;

        for (int i = 0; i < 3; i++)
            stats.RecordPacket(packet, TrafficDirection.Outbound);

        stats.RecordDecision(allowed: true, length: 100, packet);
        stats.RecordDecision(allowed: false, length: 200, packet);
        stats.RecordDecision(allowed: false, length: 300, packet);

        var snapshot = stats.Snapshot();

        Assert.Equal(3, snapshot.Total);
        Assert.Equal(1, snapshot.Allowed);
        Assert.Equal(2, snapshot.Denied);
        Assert.Equal(100, snapshot.AllowedBytes);
        Assert.Equal(500, snapshot.DeniedBytes);
        Assert.Equal(3, snapshot.Outbound);
    }

    private static FirewallLogEntry MakeEntry(
        string src, int sport, string dst, int dport, RuleAction action, string ruleName) =>
        new()
        {
            Timestamp = DateTimeOffset.Now,
            Direction = TrafficDirection.Outbound,
            Action = action,
            Protocol = "TCP",
            SourceAddress = src,
            SourcePort = sport,
            DestinationAddress = dst,
            DestinationPort = dport,
            PacketLength = 74,
            RuleId = 1,
            RuleName = ruleName,
            Reason = ruleName,
        };
}