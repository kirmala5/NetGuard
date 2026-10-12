using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetGuard.Core.Engine;
using NetGuard.Core.Rules;

namespace NetGuard.Core.Configuration;

/// <summary>Результат чтения конфигурации: данные либо список проблем.</summary>
public sealed record ConfigLoadResult(
    FirewallConfig? Config,
    RuleSet? RuleSet,
    List<string> Errors,
    List<string> Warnings)
{
    public bool Success => Config is not null && RuleSet is not null && Errors.Count == 0;
}

/// <summary>
/// Чтение и сохранение конфигурации в JSON.
/// Пункт 3.1 ТЗ № 8. Формат выбран JSON: он не требует внешних зависимостей,
/// а правила остаются в одном читаемом файле.
/// </summary>
public static class ConfigLoader
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>Читает конфигурацию и готовит набор правил к работе.</summary>
    public static ConfigLoadResult Load(string path)
    {
        var errors = new List<string>();
        var warnings = new List<string>();

        if (!File.Exists(path))
        {
            errors.Add($"Файл конфигурации не найден: {path}");
            return new ConfigLoadResult(null, null, errors, warnings);
        }

        FirewallConfig? config;
        try
        {
            string json = File.ReadAllText(path);
            config = JsonSerializer.Deserialize<FirewallConfig>(json, Options);
        }
        catch (JsonException ex)
        {
            errors.Add($"Некорректный JSON в {path}: {ex.Message}");
            return new ConfigLoadResult(null, null, errors, warnings);
        }
        catch (IOException ex)
        {
            errors.Add($"Не удалось прочитать {path}: {ex.Message}");
            return new ConfigLoadResult(null, null, errors, warnings);
        }

        if (config is null)
        {
            errors.Add($"Файл {path} не содержит конфигурации.");
            return new ConfigLoadResult(null, null, errors, warnings);
        }

        config.Capture ??= new CaptureOptions();
        config.Logging ??= new LoggingOptions();
        config.Rules ??= [];

        Validate(config, warnings);

        var ruleSet = RuleSet.Create(config.Rules, config.DefaultAction, out List<string> ruleErrors);
        errors.AddRange(ruleErrors);

        warnings.AddRange(ruleSet.Analyse());

        return errors.Count > 0
            ? new ConfigLoadResult(config, ruleSet, errors, warnings)
            : new ConfigLoadResult(config, ruleSet, errors, warnings);
    }

    /// <summary>Сохраняет конфигурацию в JSON.</summary>
    public static void Save(FirewallConfig config, string path)
    {
        ArgumentNullException.ThrowIfNull(config);

        string? directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);

        string json = JsonSerializer.Serialize(config, Options);

        // Атомарная запись: временный файл + замена, чтобы прерывание
        // не оставило после себя обрезанный rules.json.
        string temp = path + ".tmp";
        File.WriteAllText(temp, json);
        File.Move(temp, path, overwrite: true);
    }

    private static void Validate(FirewallConfig config, List<string> warnings)
    {
        if (config.Capture.QueueLength is < 64 or > 1_000_000)
        {
            warnings.Add($"QueueLength={config.Capture.QueueLength} выходит за рабочий диапазон 64…1000000.");
            config.Capture.QueueLength = Math.Clamp(config.Capture.QueueLength, 64, 1_000_000);
        }

        if (config.Capture.QueueSize is < 0 or > 256 * 1024 * 1024)
        {
            warnings.Add($"QueueSize={config.Capture.QueueSize} выходит за рабочий диапазон 0…268435456.");
            config.Capture.QueueSize = Math.Clamp(config.Capture.QueueSize, 0, 256 * 1024 * 1024);
        }

        if (config.Logging.MemoryBufferSize < 0)
        {
            warnings.Add("MemoryBufferSize не может быть отрицательным.");
            config.Logging.MemoryBufferSize = 0;
        }

        // Самая частая ошибка в учебных конфигурациях: забытый default action.
        if (config.DefaultAction == RuleAction.Deny && config.Rules.Count == 0)
        {
            warnings.Add(
                "DefaultAction=Deny и список правил пуст — весь трафик будет отброшен. " +
                "Добавьте правило на исходящий трафик или смените политику по умолчанию.");
        }
    }

    /// <summary>
    /// Конфигурация по умолчанию: безопасный профиль «всё наружу разрешено,
    /// входящие явно разрешенные порты, остальное запрещено».
    /// </summary>
    public static FirewallConfig CreateDefault()
    {
        var config = new FirewallConfig
        {
            DefaultAction = RuleAction.Deny,
            Capture = new CaptureOptions
            {
                Filter = FirewallOptions.DefaultFilter,
                IncludeLoopback = false,
                Priority = 0,
                QueueLength = 8192,
                QueueSize = 32 * 1024 * 1024,
            },
            Logging = new LoggingOptions
            {
                Enabled = true,
                Directory = "logs",
                FileNameTemplate = "firewall-{date}.csv",
                LogAllowed = false,
                LogDenied = true,
                MemoryBufferSize = 1000,
            },
        };

        config.Rules.Add(new Rule
        {
            Name = "Разрешить DNS (исходящий UDP/53)",
            Action = RuleAction.Allow,
            Protocol = "Udp",
            Direction = RuleDirection.Outbound,
            DestinationPort = "53",
        });

        config.Rules.Add(new Rule
        {
            Name = "Разрешить DNS (входящий ответ UDP/53)",
            Action = RuleAction.Allow,
            Protocol = "Udp",
            Direction = RuleDirection.Inbound,
            SourcePort = "53",
        });

        config.Rules.Add(new Rule
        {
            Name = "Разрешить HTTPS (исходящий TCP/443)",
            Action = RuleAction.Allow,
            Protocol = "Tcp",
            Direction = RuleDirection.Outbound,
            DestinationPort = "443",
        });

        config.Rules.Add(new Rule
        {
            Name = "Разрешить HTTP (исходящий TCP/80)",
            Action = RuleAction.Allow,
            Protocol = "Tcp",
            Direction = RuleDirection.Outbound,
            DestinationPort = "80",
        });

        config.Rules.Add(new Rule
        {
            Name = "Разрешить loopback",
            Action = RuleAction.Allow,
            Direction = RuleDirection.Any,
            SourceAddress = "127.0.0.0/8",
            DestinationAddress = "127.0.0.0/8",
        });

        config.Rules.Add(new Rule
        {
            Name = "Разрешить входящий ICMP (ping)",
            Action = RuleAction.Allow,
            Protocol = "Icmp",
            Direction = RuleDirection.Inbound,
        });

        config.Rules.Add(new Rule
        {
            Name = "Заблокировать Telnet (TCP/23)",
            Action = RuleAction.Deny,
            Protocol = "Tcp",
            DestinationPort = "23",
            Log = true,
        });

        config.Rules.Add(new Rule
        {
            Name = "Заблокировать входящий SMB (TCP/445)",
            Action = RuleAction.Deny,
            Protocol = "Tcp",
            Direction = RuleDirection.Inbound,
            DestinationPort = "445",
        });

        return config;
    }
}