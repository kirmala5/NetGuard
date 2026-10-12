using System.Globalization;
using NetGuard.Cli;
using NetGuard.Cli.Web;
using NetGuard.Core.Configuration;
using NetGuard.Core.Engine;
using NetGuard.Core.Rules;
using NetGuard.Core.Statistics;

// Русские сообщения в консоли cmd.exe по умолчанию показываются кракозябрами:
// кодировка консоли (обычно CP866) не совпадает с UTF-8, в котором
// компилятор сохраняет строки. Принудительно переключаем вывод на UTF-8.
try
{
    Console.OutputEncoding = System.Text.Encoding.UTF8;
    Console.InputEncoding = System.Text.Encoding.UTF8;
}
catch
{
    // Перенаправлённый вывод или неподдерживаемая консоль — не критично.
}

var options = CommandLineParser.Parse(args);

if (options.Help || options.Command is "help" or "-h" or "--help")
{
    Console.WriteLine(CommandLineParser.Usage);
    return 0;
}

// Файл конфигурации: явный путь, иначе rules.json рядом с программой.
string configPath = options.ConfigPath
    ?? Path.Combine(AppContext.BaseDirectory, CommandLineParser.DefaultConfigName);

switch (options.Command)
{
    case "genconfig":
        return Command.GenConfig(configPath);

    case "check":
        return Command.Check(configPath);

    case "rules":
        return Command.ShowRules(configPath);

    case "run":
        return await Command.RunAsync(options, configPath);

    default:
        Console.Error.WriteLine($"Неизвестная команда: {options.Command}");
        Console.WriteLine();
        Console.WriteLine(CommandLineParser.Usage);
        return 2;
}

/// <summary>Реализация команд командной строки.</summary>
internal static class Command
{
    public static int GenConfig(string path)
    {
        if (File.Exists(path) && !Confirm($"Файл {path} уже существует. Перезаписать? (д/н) "))
            return 1;

        try
        {
            ConfigLoader.Save(ConfigLoader.CreateDefault(), path);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Не удалось создать {path}: {ex.Message}");
            return 1;
        }

        Console.WriteLine($"Создана конфигурация по умолчанию: {path}");
        Console.WriteLine("Проверьте её командой:  netguard check " + path);
        return 0;
    }

    public static int Check(string path)
    {
        var result = ConfigLoader.Load(path);

        foreach (var warning in result.Warnings)
            Console.WriteLine($"  ! {warning}");

        foreach (var error in result.Errors)
            Console.WriteLine($"  ✗ {error}");

        if (result.Success)
        {
            var set = result.RuleSet!;
            Console.WriteLine();
            Console.WriteLine($"Файл:              {path}");
            Console.WriteLine($"Правил:            {set.Count}");
            Console.WriteLine($"По умолчанию:      {set.DefaultAction}");
            Console.WriteLine($"Загружено:         {set.LoadedAt:yyyy-MM-dd HH:mm:ss}");

            if (set.Count > 0)
            {
                Console.WriteLine();
                Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
                    "{0,-4} {1,-7} {2,-6} {3,-26} {4,-26} ИМЯ",
                    "#", "ДЕЙСТВИЕ", "ПРОТОКОЛ", "ИСТОЧНИК", "ПОЛУЧАТЕЛЬ"));
                Console.WriteLine(new string('-', 110));

                foreach (var rule in set.Rules)
                {
                    string src = $"{rule.SourceAddress ?? "any"}:{rule.SourcePort}";
                    string dst = $"{rule.DestinationAddress ?? "any"}:{rule.DestinationPort}";
                    Console.WriteLine(
                        $"{rule.Priority,-4} {rule.Action,-7} {rule.Protocol,-6} {src,-26} {dst,-26} {rule.Name}");
                }
            }

            Console.WriteLine();
            Console.WriteLine("Конфигурация корректна.");
            return 0;
        }

        Console.Error.WriteLine();
        Console.Error.WriteLine($"Конфигурация содержит {result.Errors.Count} ошибк(и).");
        return 1;
    }

    public static int ShowRules(string path)
    {
        var result = ConfigLoader.Load(path);

        if (result.RuleSet is null)
        {
            Console.Error.WriteLine(string.Join("; ", result.Errors));
            return 1;
        }

        Console.WriteLine($"Правила из {path}");
        Console.WriteLine($"По умолчанию: {result.RuleSet.DefaultAction}; всего {result.RuleSet.Count}");
        Console.WriteLine();

        foreach (var rule in result.RuleSet.Rules)
            Console.WriteLine($"{rule.Priority,3}. [{rule.Action,-5}] {rule.Describe()}   — {rule.Name}");

        return 0;
    }

    public static async Task<int> RunAsync(CliOptions options, string configPath)
    {
        if (!File.Exists(configPath))
        {
            Console.Error.WriteLine($"Файл конфигурации не найден: {configPath}");
            Console.Error.WriteLine("Создать конфигурацию по умолчанию? (д/н)");
            if (!Confirm("", defaultAnswer: true))
                return 1;

            try
            {
                ConfigLoader.Save(ConfigLoader.CreateDefault(), configPath);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Не удалось создать {configPath}: {ex.Message}");
                return 1;
            }

            Console.WriteLine($"Создана конфигурация: {configPath}");
        }

        var host = new FirewallHost(configPath, options.IncludeLoopback, options.LogAllowed);

        Banner(configPath);

        if (!host.TryStart())
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine("Запуск не удался: " + (host.LastError ?? "неизвестная причина"));

            if (!FirewallOptions.IsElevated())
            {
                Console.Error.WriteLine();
                Console.Error.WriteLine(FirewallOptions.ElevationHint);
            }

            // Без веб-интерфейса продолжать нечего: сообщаем код ошибки.
            // С веб-интерфейсом остаёмся работать — панель покажет состояние
            // и причину сбоя, что удобнее для разбора проблем с драйвером.
            if (!options.WebEnabled)
                return 1;

            Console.Error.WriteLine();
            Console.Error.WriteLine("Веб-интерфейс всё равно запускается: панель покажет состояние и ошибку.");
        }
        else
        {
            foreach (var warning in host.LastWarnings)
                Console.WriteLine($"  ! {warning}");

            var started = host.GetStatus();
            Console.WriteLine($"Фильтр перехвата: {started.Filter}");
            Console.WriteLine($"Правил: {started.RuleCount}, по умолчанию: {started.DefaultAction}");
            Console.WriteLine($"Журнал: {started.LogFile ?? "(в памяти)"}");
        }

        if (options.WebEnabled)
            Console.WriteLine("Веб-интерфейс включается на " + options.WebUrl);

        Console.WriteLine();
        Console.WriteLine("Клавиши: s — статистика, r — правила, l — события, f — перечитать правила, q — выход");
        Console.WriteLine();

        using var stopping = new CancellationTokenSource();

        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            stopping.Cancel();
        };

        // Консольные команды и веб-сервер работают параллельно.
        var consoleTask = ConsoleLoopAsync(host, stopping.Token);
        var webTask = options.WebEnabled
            ? Task.Run(() => WebInterface.StartAsync(host, options.WebUrl), stopping.Token)
            : Task.CompletedTask;

        try
        {
            await Task.WhenAll(consoleTask, webTask).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Нормальное завершение по Ctrl+C.
        }

        Console.WriteLine();
        Console.WriteLine("Остановка…");
        await host.DisposeAsync().ConfigureAwait(false);
        Console.WriteLine("Остановлено.");
        return 0;
    }

    private static void Banner(string configPath)
    {
        string version = typeof(Command).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
        string rights = FirewallOptions.IsElevated()
            ? "права администратора: есть"
            : "права администратора: НЕТ — перехват невозможен";

        Console.WriteLine("NetGuard — межсетевой экран с фильтрацией пакетов");
        Console.WriteLine(new string('=', 56));
        Console.WriteLine($" Версия:     {version}");
        Console.WriteLine($" Конфигурация: {configPath}");
        Console.WriteLine($" {rights}");
        Console.WriteLine();
    }

    /// <summary>Цикл консольных команд, работающий, пока не нажата q или Ctrl+C.</summary>
    private static async Task ConsoleLoopAsync(FirewallHost host, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                if (!Console.KeyAvailable)
                {
                    await Task.Delay(60, token).ConfigureAwait(false);
                    continue;
                }
            }
            catch (InvalidOperationException)
            {
                // Нет интерактивной консоли (перенаправление вывода):
                // просто ждём отмены.
                await Task.Delay(500, token).ConfigureAwait(false);
                continue;
            }

            var key = Console.ReadKey(intercept: true);

            switch (char.ToLowerInvariant(key.KeyChar))
            {
                case 's':
                    PrintStats(host);
                    break;

                case 'r':
                    PrintRules(host);
                    break;

                case 'l':
                    PrintLogs(host);
                    break;

                case 'f':
                    if (host.TryReloadRules(out var set))
                        Console.WriteLine($"Правила перечитаны: {set?.Count ?? 0} шт.");
                    else
                        Console.Error.WriteLine("Ошибка: " + host.LastError);
                    break;

                case 'q':
                    return;

                default:
                    if (key.Key == ConsoleKey.Enter)
                    {
                        var status = host.GetStatus();
                        Console.WriteLine($"  состояние: {status.State}, пакетов: {status.Statistics.Total}");
                    }

                    break;
            }
        }
    }

    private static void PrintStats(FirewallHost host)
    {
        var s = host.GetStatus().Statistics;

        Console.WriteLine();
        Console.WriteLine($"Состояние: {host.GetStatus().State}");
        Console.WriteLine($"Пакетов:   всего {s.Total}, разрешено {s.Allowed}, заблокировано {s.Denied}");
        Console.WriteLine($"Объём:     принято {Bytes(s.AllowedBytes)}, отброшено {Bytes(s.DeniedBytes)}");
        Console.WriteLine($"Протоколы: TCP {s.Tcp}, UDP {s.Udp}, ICMP {s.Icmp}, ICMPv6 {s.IcmpV6}");
        Console.WriteLine($"Направления: исходящий {s.Outbound}, входящий {s.Inbound}");

        if (s.TopBlocked.Count > 0)
        {
            Console.WriteLine("Чаще всего блокируется:");
            foreach (var t in s.TopBlocked)
                Console.WriteLine($"   {t.Address,-40} {t.Packets}");
        }
    }

    private static void PrintRules(FirewallHost host)
    {
        var set = host.CurrentRules;

        Console.WriteLine();
        Console.WriteLine($"Правила ({set.Count}), по умолчанию: {set.DefaultAction}");
        foreach (var r in set.Rules)
        {
            Console.WriteLine(
                $"{r.Priority,3}. [{r.Action,-5}] {r.Describe(),-46} {r.Name}  ({r.HitCount} пак.)");
        }
    }

    private static void PrintLogs(FirewallHost host)
    {
        var entries = host.Engine?.MemoryLog.Tail(20) ?? [];

        Console.WriteLine();
        if (entries.Count == 0)
        {
            Console.WriteLine("Событий нет (возможно, разрешённые пакеты не логируются).");
            return;
        }

        foreach (var e in entries)
            Console.WriteLine("  " + e.ToDisplayString());
    }

    private static string Bytes(double value)
    {
        string[] units = ["Б", "КБ", "МБ", "ГБ"];
        int i = 0;

        while (value >= 1024 && i < units.Length - 1)
        {
            value /= 1024;
            i++;
        }

        return $"{value:0.#} {units[i]}";
    }

    private static bool Confirm(string message, bool defaultAnswer = false)
    {
        if (Console.IsInputRedirected)
            return defaultAnswer;

        Console.Write(message);

        var answer = Console.ReadLine();
        if (answer is null)
            return defaultAnswer;

        answer = answer.Trim().ToLower(CultureInfo.InvariantCulture);
        if (answer.Length == 0)
            return defaultAnswer;

        return answer is "д" or "y" or "yes" or "1" or "да";
    }
}