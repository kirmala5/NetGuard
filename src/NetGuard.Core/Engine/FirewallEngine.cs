using NetGuard.Core.Configuration;
using NetGuard.Core.Logging;
using NetGuard.Core.Protocols;
using NetGuard.Core.Rules;
using NetGuard.Core.Statistics;

namespace NetGuard.Core.Engine;

public enum FirewallState
{
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
}

/// <summary>Снимок состояния файрвола для CLI и веб-интерфейса.</summary>
public sealed record FirewallStatus
{
    public required FirewallState State { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required string Filter { get; init; }
    public required int RuleCount { get; init; }
    public required RuleAction DefaultAction { get; init; }
    public required bool Elevated { get; init; }
    public required string Version { get; init; }
    public string? LogFile { get; init; }
    public string? LastError { get; init; }
    public required StatisticsSnapshot Statistics { get; init; }
}

/// <summary>
/// Файрвол: связывает перехват пакетов, список правил, журнал и статистику.
///
/// Экземпляр владеет одним дескриптором WinDivert, поэтому работает
/// только в одном процессе. Набор правил хранится в поле с заменой по
/// ссылке — поток обработки пакетов читает снимок, а подмена выполняется
/// без блокировки, поэтому правила можно менять на лету.
/// </summary>
public sealed class FirewallEngine : IAsyncDisposable
{
    private readonly CaptureSettings _captureSettings;
    private readonly LoggingOptions _loggingOptions;

    private readonly TrafficStatistics _statistics = new();
    private readonly MemoryEventSink _memorySink;

    private RuleSet _rules;
    private CsvEventSink? _csvSink;
    private WinDivertCapture? _capture;

    private CancellationTokenSource? _cts;
    private Task? _runTask;
    private FirewallState _state = FirewallState.Stopped;
    private DateTimeOffset _startedAt;
    private string? _lastError;

    public FirewallEngine(FirewallConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        var errors = new List<string>();
        _rules = RuleSet.Create(config.Rules, config.DefaultAction, out errors);

        if (errors.Count > 0)
            _lastError = string.Join("; ", errors);

        string filter = config.Capture.IncludeLoopback
            ? FirewallOptions.LoopbackFilter
            : config.Capture.Filter;

        _captureSettings = new CaptureSettings(
            Filter: filter,
            Priority: config.Capture.Priority,
            QueueLength: config.Capture.QueueLength,
            QueueSize: config.Capture.QueueSize,
            RepairChecksums: true);

        _loggingOptions = config.Logging;
        _memorySink = new MemoryEventSink(config.Logging.MemoryBufferSize);
    }

    public FirewallState State => _state;
    public RuleSet Rules => Volatile.Read(ref _rules);
    public MemoryEventSink MemoryLog => _memorySink;
    public DateTimeOffset StartedAt => _startedAt;

    /// <summary>Событие состояния — веб-интерфейс подписан на него для live-обновлений.</summary>
    public event EventHandler<FirewallState>? StateChanged;

    /// <summary>Заменяет набор правил на лету (горячая перезагрузка).</summary>
    public void ReplaceRules(RuleSet ruleSet, RuleAction defaultAction)
    {
        ArgumentNullException.ThrowIfNull(ruleSet);
        Volatile.Write(ref _rules, ruleSet);
        GC.KeepAlive(defaultAction);
    }

    /// <summary>Запускает перехват трафика.</summary>
    public void Start()
    {
        if (_state is FirewallState.Running or FirewallState.Starting)
            return;

        if (!FirewallOptions.IsElevated())
        {
            _state = FirewallState.Failed;
            _lastError = "Недостаточно прав. " + FirewallOptions.ElevationHint;
            OnStateChanged();
            throw new UnauthorizedAccessException(_lastError);
        }

        _state = FirewallState.Starting;
        OnStateChanged();

        try
        {
            CreateSinks();

            var capture = new WinDivertCapture(_captureSettings);
            capture.Open();
            _capture = capture;

            _cts = new CancellationTokenSource();
            _startedAt = DateTimeOffset.Now;
            _state = FirewallState.Running;
            _lastError = null;

            _runTask = Task.Run(() => capture.RunAsync(
                Rules,
                HandleDecisionAsync,
                new StatisticsCounterSink(_statistics),
                _cts.Token));

            OnStateChanged();
        }
        catch (Exception ex)
        {
            _state = FirewallState.Failed;
            _lastError = Describe(ex);
            _capture?.Dispose();
            _capture = null;
            DisposeSinks();
            OnStateChanged();
            throw;
        }
    }

    /// <summary>Останавливает перехват и освобождает дескриптор.</summary>
    public async Task StopAsync()
    {
        if (_state == FirewallState.Stopped)
            return;

        _state = FirewallState.Stopping;
        OnStateChanged();

        if (_cts is not null)
        {
            await _cts.CancelAsync().ConfigureAwait(false);
        }

        if (_runTask is not null)
        {
            try
            {
                await _runTask.ConfigureAwait(false);
            }
            catch
            {
                // Ошибка цикла перехвата уже записана в LastError.
            }

            _runTask = null;
        }

        _cts?.Dispose();
        _cts = null;

        _capture?.Dispose();
        _capture = null;

        DisposeSinks();

        _state = FirewallState.Stopped;
        OnStateChanged();
    }

    /// <summary>
    /// Решение по пакету: запись в журналы. Вызывается из цикла перехвата,
    /// поэтому не должно блокировать — файловые приёмники пишут под замком.
    /// </summary>
    private ValueTask HandleDecisionAsync(PacketOutcome outcome)
    {
        bool shouldLog =
            (outcome.Allowed && _loggingOptions.LogAllowed) ||
            (!outcome.Allowed && _loggingOptions.LogDenied);

        if (shouldLog)
        {
            var entry = FirewallLogEntry.FromPacket(
                outcome.Info, outcome.Direction, outcome.Action, outcome.Rule, outcome.Length);

            _memorySink.Write(entry);
            _csvSink?.Write(entry);
        }

        return ValueTask.CompletedTask;
    }

    private void CreateSinks()
    {
        if (!_loggingOptions.Enabled)
            return;

        try
        {
            _csvSink = new CsvEventSink(_loggingOptions.Directory, _loggingOptions.FileNameTemplate);
        }
        catch (Exception ex)
        {
            // Недоступный каталог журнала не должен мешать фильтрации:
            // продолжаем вести журнал в памяти и сообщаем пользователю.
            _lastError = "Журнал в файл недоступен: " + Describe(ex);
        }
    }

    private void DisposeSinks()
    {
        _csvSink?.Dispose();
        _csvSink = null;
    }

    public FirewallStatus GetStatus()
    {
        var ruleSet = Rules;

        return new FirewallStatus
        {
            State = _state,
            StartedAt = _startedAt,
            Filter = _captureSettings.Filter,
            RuleCount = ruleSet.Count,
            DefaultAction = ruleSet.DefaultAction,
            Elevated = FirewallOptions.IsElevated(),
            Version = ThisAssembly.Version,
            LogFile = _csvSink?.CurrentFile,
            LastError = _lastError,
            Statistics = _statistics.Snapshot(),
        };
    }

    private static string Describe(Exception ex)
    {
        var baseMessage = ex switch
        {
            UnauthorizedAccessException => ex.Message,
            System.ComponentModel.Win32Exception win32 =>
                $"код {win32.NativeErrorCode}: {win32.Message}. " +
                "Проверьте, что драйвер перехвата установлен и вы запущены от администратора.",
            DllNotFoundException or EntryPointNotFoundException =>
                "Не найдена библиотека перехвата пакетов (WinDivert.dll). " +
                "Переустановите/пересоберите проект, чтобы восстановить нативные файлы.",
            _ => ex.Message,
        };

        return baseMessage;
    }

    private void OnStateChanged() => StateChanged?.Invoke(this, _state);

    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        _cts?.Dispose();
    }
}

internal static class ThisAssembly
{
    public static string Version =>
        typeof(FirewallEngine).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
}