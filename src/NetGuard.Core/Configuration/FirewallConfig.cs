using System.Text.Json.Serialization;
using NetGuard.Core.Engine;
using NetGuard.Core.Rules;

namespace NetGuard.Core.Configuration;

/// <summary>Параметры захвата трафика.</summary>
public sealed class CaptureOptions
{
    /// <summary>Фильтр WinDivert. По умолчанию — весь IP-трафик без loopback.</summary>
    public string Filter { get; set; } = FirewallOptions.DefaultFilter;

    /// <summary>Захватывать ли трафик loopback-интерфейса.</summary>
    public bool IncludeLoopback { get; set; }

    /// <summary>
    /// Приоритет перехвата в WinDivert: чем выше значение, тем раньше
    /// пакет попадёт к файрволу. 0 — обычный приоритет.
    /// </summary>
    public int Priority { get; set; }

    /// <summary>Размер очереди перехвата в пакетах.</summary>
    public int QueueLength { get; set; } = 8192;

    /// <summary>Размер очереди перехвата в байтах.</summary>
    public int QueueSize { get; set; } = 32 * 1024 * 1024;
}

/// <summary>Параметры журналирования.</summary>
public sealed class LoggingOptions
{
    /// <summary>Включено ли ведение журнала.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Каталог для файлов журнала (пусто — рядом с исполняемым файлом).</summary>
    public string Directory { get; set; } = "logs";

    /// <summary>Шаблон имени файла. {date} подставляется как yyyy-MM-dd.</summary>
    public string FileNameTemplate { get; set; } = "firewall-{date}.csv";

    /// <summary>Писать ли в журнал разрешённые пакеты.</summary>
    public bool LogAllowed { get; set; }

    /// <summary>Писать ли в журнал отброшенные пакеты.</summary>
    public bool LogDenied { get; set; } = true;

    /// <summary>Сколько событий хранить в памяти для веб-интерфейса и команды log.</summary>
    public int MemoryBufferSize { get; set; } = 1000;
}

/// <summary>
/// Полная конфигурация файрвола (п. 3.1 ТЗ, № 8 — загрузка правил из файла).
/// Соответствует JSON-файлу rules.json.
/// </summary>
public sealed class FirewallConfig
{
    /// <summary>Решение для пакетов, не подошедших ни под одно правило.</summary>
    public RuleAction DefaultAction { get; set; } = RuleAction.Deny;

    /// <summary>Параметры захвата.</summary>
    public CaptureOptions Capture { get; set; } = new();

    /// <summary>Параметры журнала.</summary>
    public LoggingOptions Logging { get; set; } = new();

    /// <summary>Список правил в порядке приоритета.</summary>
    public List<Rule> Rules { get; set; } = [];
}