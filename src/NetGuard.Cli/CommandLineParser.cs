namespace NetGuard.Cli;

/// <summary>Разобранная командная строка.</summary>
public sealed record CliOptions
{
    public string Command { get; init; } = "help";
    public string? ConfigPath { get; init; }
    public bool WebEnabled { get; init; }
    public string WebUrl { get; init; } = "http://localhost:8080";
    public bool IncludeLoopback { get; init; }
    public bool LogAllowed { get; init; }
    public bool Verbose { get; init; }
    public string? DefaultAction { get; init; }
    public bool Help { get; init; }
}

/// <summary>
/// Разбор аргументов командной строки.
///
/// Разбор написан вручную, а не через System.CommandLine: набор команд
/// маленький и фиксированный, а лишняя зависимость в проекте, который
/// должны запускать одной командой, не нужна.
/// </summary>
public static class CommandLineParser
{
    public const string DefaultConfigName = "rules.json";

    public static CliOptions Parse(string[] args)
    {
        // Без аргументов запускаем файрвол с веб-панелью, а не показываем справку.
        // Двойной клик по .exe должен запускать программу по назначению;
        // справка в окне, которое сразу закрывается, нефункциональна.
        if (args.Length == 0)
        {
            return new CliOptions
            {
                Command = "run",
                WebEnabled = true,
            };
        }

        string command = args[0].ToLowerInvariant();
        string? config = null;
        string? webUrl = null;
        bool webEnabled = false;
        bool loopback = false;
        bool logAllowed = false;
        bool verbose = false;
        bool help = false;
        string? defaultAction = null;

        for (int i = 1; i < args.Length; i++)
        {
            string arg = args[i];

            switch (arg)
            {
                case "-h" or "--help" or "/?":
                    help = true;
                    break;

                case "-c" or "--config":
                    config = Next(args, ref i) ?? config;
                    break;

                case "-w" or "--web":
                    webEnabled = true;

                    // Значение необязательно: --web или --web http://localhost:9000
                    if (i + 1 < args.Length && !args[i + 1].StartsWith('-'))
                    {
                        string candidate = args[i + 1];

                        if (candidate.Contains("://", StringComparison.Ordinal))
                        {
                            webUrl = candidate;

                            // Обязательно поглощаем аргумент: иначе он попадёт
                            // в позиционные параметры и будет принят
                            // за путь к файлу конфигурации.
                            i++;
                        }
                    }

                    break;

                case "--no-web":
                    webEnabled = false;
                    break;

                case "--loopback":
                    loopback = true;
                    break;

                case "--log-allowed":
                    logAllowed = true;
                    break;

                case "-v" or "--verbose":
                    verbose = true;
                    break;

                case "--default-action":
                    defaultAction = Next(args, ref i);
                    break;

                default:
                    // Позиционный аргумент: путь к файлу конфигурации.
                    if (!arg.StartsWith('-'))
                        config ??= arg;

                    break;
            }
        }

        webUrl ??= "http://localhost:8080";

        // Проверка и просмотр конфигурации не требуют веб-интерфейса.
        if (command is "run" && !help)
            webEnabled = webEnabled || args.Contains("--web");

        return new CliOptions
        {
            Command = command,
            ConfigPath = config,
            WebEnabled = webEnabled,
            WebUrl = webUrl,
            IncludeLoopback = loopback,
            LogAllowed = logAllowed,
            Verbose = verbose,
            DefaultAction = defaultAction,
            Help = help,
        };
    }

    private static string? Next(string[] args, ref int index)
    {
        if (index + 1 >= args.Length)
            return null;

        index++;
        return args[index];
    }

    /// <summary>Текст справки по командам.</summary>
    public static string Usage =>
        """
        NetGuard — межсетевой экран с фильтрацией пакетов (WPF-нет: WPF не требуется,
        это консольное приложение + веб-интерфейс).

        ИСПОЛЬЗОВАНИЕ
          netguard <команда> [параметры]

        КОМАНДЫ
          run                 Запустить перехват трафика и применение правил
          check [файл]        Проверить конфигурацию, не перехватывая трафик
          genconfig [файл]    Создать конфигурацию по умолчанию
          rules [файл]        Показать загруженные правила
          help                Эта справка

        ПАРАМЕТРЫ КОМАНДЫ run
          -c, --config <путь>   Файл конфигурации (по умолчанию rules.json)
          -w, --web [url]       Включить веб-интерфейс (по умолчанию http://localhost:8080)
          --no-web              Не включать веб-интерфейс
          --loopback            Перехватывать трафик loopback (для отладки на одной машине)
          --log-allowed         Записывать в журнал и разрешённые пакеты
          --default-action <a>  Переопределить политику по умолчанию: allow | deny
          -v, --verbose         Печатать события в консоль

        УПРАВЛЕНИЕ В КОНСОЛИ ПРИ РАБОТЕ
          s — статистика,  r — правила,  l — последние события,
          f — перечитать rules.json,  q — выход

        ВАЖНО
          Перехват пакетов выполняется через драйвер WinDivert, поэтому программа
          должна быть запущена от имени администратора.
        """;
}