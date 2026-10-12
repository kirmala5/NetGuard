using NetGuard.Core.Configuration;
using NetGuard.Core.Engine;
using NetGuard.Core.Rules;
using NetGuard.Core.Statistics;

namespace NetGuard.Cli;

/// <summary>
/// Обёртка над движком для обоих интерфейсов (CLI и веб).
///
/// Существует потому, что перехват может принадлежать только одному
/// процессу: CLI и веб работают в одном процессе и делят этот объект,
/// поэтому состояние не может разъехаться между двумя окнами.
/// </summary>
public sealed class FirewallHost : IAsyncDisposable
{
    private readonly string _configPath;
    private readonly object _gate = new();
    private FirewallEngine? _engine;
    private RuleSet? _lastLoadedRules;

    public FirewallHost(string configPath, bool includeLoopback, bool logAllowed)
    {
        _configPath = configPath;
        ConfigPath = configPath;
        IncludeLoopback = includeLoopback;
        LogAllowed = logAllowed;
    }

    public string ConfigPath { get; }
    public bool IncludeLoopback { get; }
    public bool LogAllowed { get; }

    public FirewallEngine? Engine
    {
        get { lock (_gate) return _engine; }
    }

    public bool IsRunning => Engine?.State == FirewallState.Running;

    /// <summary>Последняя ошибка, возникшая при работе с конфигурацией или запуском.</summary>
    public string? LastError { get; private set; }

    public IReadOnlyList<string> LastWarnings { get; private set; } = [];

    /// <summary>
    /// Загружает конфигурацию и поднимает перехват.
    /// Возвращает false вместе с заполненным <see cref="LastError"/>, если
    /// конфигурация нечитаема или прав недостаточно.
    /// </summary>
    public bool TryStart()
    {
        lock (_gate)
        {
            if (_engine is { State: FirewallState.Running or FirewallState.Starting })
                return true;

            var load = ConfigLoader.Load(_configPath);

            if (!load.Success || load.Config is null || load.RuleSet is null)
            {
                LastError = string.Join("; ", load.Errors);
                LastWarnings = load.Warnings;
                return false;
            }

            LastWarnings = load.Warnings;

            // Переопределения из командной строки важнее файла:
            // так один и тот же rules.json работает в разных режимах запуска.
            if (IncludeLoopback)
                load.Config.Capture.IncludeLoopback = true;

            if (LogAllowed)
                load.Config.Logging.LogAllowed = true;

            var engine = new FirewallEngine(load.Config);

            try
            {
                engine.Start();
            }
            catch (Exception ex)
            {
                LastError = ex.Message;
                return false;
            }

            _engine = engine;
            _lastLoadedRules = load.RuleSet;
            LastError = null;
            return true;
        }
    }

    /// <summary>Останавливает перехват.</summary>
    public async Task StopAsync()
    {
        FirewallEngine? engine;

        lock (_gate)
        {
            engine = _engine;
            _engine = null;
        }

        if (engine is not null)
            await engine.DisposeAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Перечитывает rules.json и применяет правила на лету — без остановки
    /// перехвата (п. 3.2 ТЗ, «горячая перезагрузка правил»).
    /// </summary>
    public bool TryReloadRules(out RuleSet? ruleSet)
    {
        ruleSet = null;

        var load = ConfigLoader.Load(_configPath);

        if (load.RuleSet is null)
        {
            LastError = string.Join("; ", load.Errors);
            return false;
        }

        LastWarnings = load.Warnings;
        LastError = load.Errors.Count > 0 ? string.Join("; ", load.Errors) : null;

        ruleSet = load.RuleSet;
        _lastLoadedRules = load.RuleSet;
        Engine?.ReplaceRules(load.RuleSet, load.RuleSet.DefaultAction);

        return true;
    }

    /// <summary>
    /// Текущий набор правил.
    ///
    /// Если перехват не запущен (например, нет прав администратора),
    /// показываем правила из файла, а не пустой набор: иначе оператор
    /// не смог бы ни посмотреть, ни проверить конфигурацию без перехвата.
    /// </summary>
    public RuleSet CurrentRules =>
        Engine?.Rules
        ?? _lastLoadedRules
        ?? LoadRulesForInspection();

    private RuleSet LoadRulesForInspection()
    {
        var load = ConfigLoader.Load(_configPath);

        return load.RuleSet ?? RuleSet.Empty(RuleAction.Deny);
    }

    /// <summary>Сохраняет набор правил в конфигурацию и применяет на лету.</summary>
    public bool TrySaveRules(IReadOnlyList<Rule> rules, RuleAction defaultAction, out string? error)
    {
        error = null;

        var load = ConfigLoader.Load(_configPath);
        var config = load.Config ?? ConfigLoader.CreateDefault();

        config.Rules = [.. rules];
        config.DefaultAction = defaultAction;

        try
        {
            ConfigLoader.Save(config, _configPath);
        }
        catch (Exception ex)
        {
            error = "Не удалось сохранить конфигурацию: " + ex.Message;
            return false;
        }

        if (!TryReloadRules(out var reloaded) || reloaded is null)
        {
            error = LastError ?? "Правила загружены, но не применены.";
            return false;
        }

        // Идентификаторы и приоритеты пересчитаны заново — сохраняем
        // приведённый набор, чтобы интерфейс показал фактический порядок.
        rules = reloaded.Rules.ToList();
        return true;
    }

    public FirewallStatus GetStatus() =>
        Engine?.GetStatus() ?? new FirewallStatus
        {
            State = FirewallState.Stopped,
            StartedAt = DateTimeOffset.MinValue,
            Filter = "—",
            RuleCount = CurrentRules.Count,
            DefaultAction = CurrentRules.DefaultAction,
            Elevated = FirewallOptions.IsElevated(),
            Version = typeof(FirewallHost).Assembly.GetName().Version?.ToString(3) ?? "0.0.0",
            LastError = LastError,
            Statistics = new TrafficStatistics().Snapshot(),
        };

    public async ValueTask DisposeAsync() => await StopAsync().ConfigureAwait(false);
}