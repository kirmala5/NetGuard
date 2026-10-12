using Divert.Windows;
using NetGuard.Core.Protocols;
using NetGuard.Core.Rules;

namespace NetGuard.Core.Engine;

/// <summary>Данные одного перехваченного пакета.</summary>
public readonly record struct CapturedPacket(
    ReadOnlyMemory<byte> Buffer,
    DivertAddress Address,
    int Length,
    PacketInfo Info,
    TrafficDirection Direction);

/// <summary>Результат обработки одного пакета.</summary>
public readonly record struct PacketOutcome(
    RuleAction Action,
    Rule? Rule,
    PacketInfo Info,
    TrafficDirection Direction,
    int Length)
{
    public bool Allowed => Action == RuleAction.Allow;
}

/// <summary>
/// Захват пакетов через WinDivert и применение списка правил.
///
/// Ключевая семантика WinDivert, определяющая весь код: дескриптор открыт
/// **без** флага <see cref="DivertFlags.Sniff"/>, поэтому перехваченный пакет
/// изъят из сетевого стека. Чтобы пропустить его дальше, его нужно вернуть
/// через <see cref="DivertService.SendAsync"/>. Просто «не отвечать» означает
/// отбрасывание пакета — это и есть блокировка.
/// </summary>
public sealed class WinDivertCapture : IDisposable
{
    private readonly string _filter;
    private readonly short _priority;
    private readonly int _queueLength;
    private readonly int _queueSize;
    private readonly bool _calculateChecksums;

    private DivertService? _service;
    private bool _disposed;

    public WinDivertCapture(CaptureSettings settings)
    {
        _filter = settings.Filter;
        _priority = checked((short)Math.Clamp(settings.Priority, short.MinValue, short.MaxValue));
        _queueLength = settings.QueueLength;
        _queueSize = settings.QueueSize;
        _calculateChecksums = settings.RepairChecksums;
    }

    /// <summary>Открывает дескриптор перехвата. Требует прав администратора.</summary>
    public void Open()
    {
        if (_service is not null)
            return;

        var filter = new DivertFilter(_filter);
        var flags = DivertFlags.None;

        _service = new DivertService(filter, DivertLayer.Network, _priority, flags);

        // Размеры очереди выставляются отдельным вызовом: конструктор
        // не принимает их, а неверные значения приводят к потере пакетов.
        if (_queueLength > 0)
            _service.QueueLength = _queueLength;

        if (_queueSize > 0)
            _service.QueueSize = _queueSize;
    }

    /// <summary>
    /// Основной цикл перехвата. Завершается при отмене <paramref name="stoppingToken"/>.
    /// </summary>
    public async Task RunAsync(
        RuleSet ruleSet,
        Func<PacketOutcome, ValueTask> onDecision,
        StatisticsCounterSink statistics,
        CancellationToken stoppingToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_service is null)
            throw new InvalidOperationException("Дескриптор перехвата не открыт.");

        // Буфер на один максимальный пакет: WinDivert складывает в буфер столько
        // пакетов, сколько в него помещается, поэтому одного пакета достаточно,
        // чтобы «пакет = вызов ReceiveAsync» и адрес всегда соответствовал буферу.
        var buffer = new byte[FirewallOptions.MaxPacketSize];
        var addresses = new DivertAddress[1];

        while (!stoppingToken.IsCancellationRequested)
        {
            DivertReceiveResult received;
            int length;
            DivertAddress address;

            try
            {
                received = await _service.ReceiveAsync(buffer, addresses, stoppingToken)
                    .ConfigureAwait(false);

                (length, _) = received;
                address = addresses[0];
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex) when (IsRecoverable(ex))
            {
                // WinDivert сообщает об отсутствии пакетов и о закрытии дескриптора
                // исключениями — это штатные ситуации, а не сбои.
                if (stoppingToken.IsCancellationRequested)
                    break;

                continue;
            }

            if (length <= 0)
                continue;

            bool outbound = address.IsOutbound;
            var direction = outbound ? TrafficDirection.Outbound : TrafficDirection.Inbound;

            PacketInfo info;
            try
            {
                info = PacketParser.Parse(buffer, 0, length, outbound);
                statistics.MarkParsed();
            }
            catch (Exception)
            {
                // Парсер не должен бросать, но страховка от фатальной ошибки
                // обязательна: файрвол не имеет права падать из-за плохого пакета.
                statistics.MarkParseFailure();
                info = PacketInfo.Empty;
            }

            var decision = ruleSet.Evaluate(info, direction);
            bool allow = decision.Action == RuleAction.Allow;

            ruleSet.RecordHit(decision.MatchedRule, length);
            statistics.Count(info, direction, allow, length);

            try
            {
                if (allow)
                {
                    // Разрешённый пакет нужно вернуть в стек — иначе он будет
                    // отброшен вместе с перехватом.
                    if (_calculateChecksums && NeedsChecksumRepair(address))
                    {
                        // При включённом аппаратном offload суммы в перехваченном
                        // пакете часто не рассчитаны; без починки получатель
                        // отбросит пакет как некорректный.
                        if (!DivertHelper.CalculateChecksums(
                                buffer.AsSpan(0, length), ref address, DivertHelperFlags.None))
                        {
                            // Не смогли пересчитать — пропускаем пакет как есть,
                            // лучше лишний пакет, чем потеря соединения.
                        }
                    }

                    await _service.SendAsync(
                        new ReadOnlyMemory<byte>(buffer, 0, length),
                        new ReadOnlyMemory<DivertAddress>(addresses, 0, 1),
                        stoppingToken).ConfigureAwait(false);
                }

                // Отброшенные пакеты намеренно не возвращаются в стек —
                // это и есть блокировка.
                await onDecision(new PacketOutcome(decision.Action, decision.MatchedRule, info, direction, length))
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex) when (IsRecoverable(ex))
            {
                // Ошибка отправки конкретного пакета не должна рвать цикл.
            }
        }
    }

    /// <summary>
    /// Нужно ли пересчитывать контрольные суммы: WinDivert сообщает о
    /// корректности сумм отдельно для IP, TCP и UDP.
    /// </summary>
    private static bool NeedsChecksumRepair(DivertAddress address)
    {
        try
        {
            return !address.IsIPChecksumValid
                || !address.IsTCPChecksumValid
                || !address.IsUDPChecksumValid;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Ошибки, после которых цикл перехвата имеет право продолжиться.
    /// Неперехватываемые (ошибки выделения памяти, нехватка ресурсов)
    /// намеренно не подавляются — они должны приводить к остановке с диагностикой.
    /// </summary>
    private static bool IsRecoverable(Exception ex) =>
        ex is System.ComponentModel.Win32Exception
            or IOException
            or ObjectDisposedException
            or InvalidOperationException;

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        _service?.Dispose();
        _service = null;
    }
}

/// <summary>Настройки перехвата, уже проверенные и нормализованные.</summary>
public sealed record CaptureSettings(
    string Filter,
    int Priority,
    int QueueLength,
    int QueueSize,
    bool RepairChecksums);

/// <summary>
/// Мост между циклом перехвата и счётчиками статистики.
/// Существует, чтобы не тянуть <see cref="Statistics.TrafficStatistics"/>
/// в низкоуровневый класс перехвата.
/// </summary>
public sealed class StatisticsCounterSink(Statistics.TrafficStatistics statistics)
{
    private readonly Statistics.TrafficStatistics _statistics =
        statistics ?? throw new ArgumentNullException(nameof(statistics));

    public void Count(in PacketInfo info, TrafficDirection direction, bool allowed, int length)
    {
        _statistics.RecordPacket(info, direction);
        _statistics.RecordDecision(allowed, length, info);
    }

    public void MarkParsed() { }

    public void MarkParseFailure() => _statistics.RecordParseFailure();
}