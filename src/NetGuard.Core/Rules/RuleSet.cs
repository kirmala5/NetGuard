using System.Net.Sockets;
using NetGuard.Core.Protocols;

namespace NetGuard.Core.Rules;

/// <summary>Результат проверки пакета по списку правил.</summary>
/// <param name="Action">Решение: пропустить или отбросить.</param>
/// <param name="MatchedRule">Совпавшее правило; null, если сработала политика по умолчанию.</param>
public readonly record struct RuleDecision(RuleAction Action, Rule? MatchedRule)
{
    /// <summary>Правило, объясняющее решение (для журнала и интерфейса).</summary>
    public string Reason => MatchedRule is { } rule
        ? $"правило #{rule.Id} «{rule.Name}»"
        : "политика по умолчанию";
}

/// <summary>
/// Упорядоченный список правил. Экземпляр неизменяем после
/// <see cref="Create"/>: это позволяет менять набор правил на лету
/// (горячая перезагрузка, правка через веб-интерфейс), пока поток
/// обработки пакетов читает старый снимок.
/// </summary>
public sealed class RuleSet
{
    private readonly Rule[] _ordered;

    private RuleSet(Rule[] ordered, RuleAction defaultAction, DateTimeOffset loadedAt)
    {
        _ordered = ordered;
        DefaultAction = defaultAction;
        LoadedAt = loadedAt;
    }

    /// <summary>Что делать с пакетом, не совпавшим ни с одним правилом.</summary>
    public RuleAction DefaultAction { get; }

    /// <summary>Момент загрузки набора — показывается в веб-интерфейсе.</summary>
    public DateTimeOffset LoadedAt { get; }

    public IReadOnlyList<Rule> Rules => _ordered;

    public int Count => _ordered.Length;

    /// <summary>
    /// Готовит набор правил к работе: разбирает строковые поля, сортирует
    /// по приоритету и перенумеровывает приоритеты, если они не заданы.
    /// </summary>
    /// <param name="rules">Правила из конфигурации (могут быть неверными).</param>
    /// <param name="defaultAction">Политика по умолчанию.</param>
    /// <param name="errors">Список ошибок по неверным правилам.</param>
    public static RuleSet Create(IEnumerable<Rule> rules, RuleAction defaultAction, out List<string> errors)
    {
        ArgumentNullException.ThrowIfNull(rules);

        errors = [];

        var prepared = new List<Rule>();
        int id = 1;

        foreach (var rule in rules)
        {
            if (!rule.TryPrepare(out string? error))
            {
                errors.Add($"Правило «{rule.Name}» (#{rule.Id}): {error}");
                continue;
            }

            rule.Id = id++;
            prepared.Add(rule);
        }

        // Порядок в файле = порядок проверки. Явный Priority задаётся редко,
        // поэтому при его отсутствии сохраняем позицию из конфигурации.
        var ordered = prepared
            .Select((rule, index) => (rule, index))
            .OrderBy(x => x.rule.Priority)
            .ThenBy(x => x.index)
            .Select((x, index) =>
            {
                x.rule.Priority = index + 1;
                return x.rule;
            })
            .ToArray();

        return new RuleSet(ordered, defaultAction, DateTimeOffset.Now);
    }

    /// <summary>Пустой набор: все пакеты пропускаются согласно политике по умолчанию.</summary>
    public static RuleSet Empty(RuleAction defaultAction) =>
        Create([], defaultAction, out _);

    /// <summary>
    /// Проверяет пакет. Правила просматриваются по порядку приоритета,
    /// побеждает первое совпавшее.
    /// </summary>
    public RuleDecision Evaluate(in PacketInfo packet, TrafficDirection direction)
    {
        for (int i = 0; i < _ordered.Length; i++)
        {
            var rule = _ordered[i];
            if (!rule.Matches(packet, direction))
                continue;

            return new RuleDecision(rule.Action, rule);
        }

        return new RuleDecision(DefaultAction, null);
    }

    /// <summary>Увеличивает счётчики совпадений. Вызывается из потока обработки пакетов.</summary>
    public void RecordHit(Rule? rule, int packetLength)
    {
        if (rule is null)
            return;

        rule.AddHit(packetLength);
    }

    /// <summary>Находит правило по идентификатору (для веб-интерфейса).</summary>
    public Rule? FindById(int id)
    {
        foreach (var rule in _ordered)
        {
            if (rule.Id == id)
                return rule;
        }

        return null;
    }

    /// <summary>
    /// Проверяет набор правил на непротиворечивость — используется командой
    /// проверки конфигурации. Возвращает предупреждения (не ошибки):
    /// пересечения допустимы, но обычно означают ошибку в правилах.
    /// </summary>
    public List<string> Analyse()
    {
        var warnings = new List<string>();

        for (int i = 0; i < _ordered.Length; i++)
        {
            for (int j = i + 1; j < _ordered.Length; j++)
            {
                if (RulesConflict(_ordered[i], _ordered[j]))
                {
                    warnings.Add(
                        $"Правила #{_ordered[i].Id} «{_ordered[i].Name}» и " +
                        $"#{_ordered[j].Id} «{_ordered[j].Name}» пересекаются: " +
                        $"сработает только #{_ordered[i].Id}.");
                }
            }
        }

        return warnings;
    }

    private static bool RulesConflict(Rule a, Rule b)
    {
        if (!a.Enabled || !b.Enabled)
            return false;

        // Одинаковые действия не конфликтуют: какое из двух правил Allow
        // сработает первым, на результат не влияет. Без этой проверки
        // предупреждения сыпались бы на каждую пару, и их перестали бы читать.
        if (a.Action == b.Action)
            return false;

        if (a.ParsedProtocol is { } pa && b.ParsedProtocol is { } pb && pa != pb)
            return false;

        if (a.Direction != RuleDirection.Any && b.Direction != RuleDirection.Any &&
            a.Direction != b.Direction)
        {
            return false;
        }

        if (!CidrBlockMayIntersect(a.SourceBlock, b.SourceBlock))
            return false;

        if (!CidrBlockMayIntersect(a.DestinationBlock, b.DestinationBlock))
            return false;

        if (!CompositePortSet.MayIntersect(a.SourcePorts, b.SourcePorts))
            return false;

        if (!CompositePortSet.MayIntersect(a.DestinationPorts, b.DestinationPorts))
            return false;

        return true;
    }

    /// <summary>Одна из подсетей не задана (значит «любая») — пересечение возможно.</summary>
    private static bool CidrBlockMayIntersect(CidrBlock? a, CidrBlock? b)
    {
        if (a is null || b is null)
            return true;

        return a.Intersects(b);
    }
}