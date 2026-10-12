using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NetGuard.Core.Engine;
using NetGuard.Core.Logging;
using NetGuard.Core.Rules;
using NetGuard.Core.Statistics;

namespace NetGuard.Cli.Web;

/// <summary>
/// Веб-интерфейс управления (п. 3.2 ТЗ, «веб-интерфейс или CLI»).
///
/// Слушает только loopback: панель управления файрволом без аутентификации,
/// доступная из сети, сама стала бы дырой в безопасности.
/// </summary>
public static class WebInterface
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
    };

    public static async Task StartAsync(FirewallHost host, string url)
    {
        var builder = WebApplication.CreateBuilder();

        builder.WebHost.UseUrls(url);

        // Минимальные API умеют внедрять только зарегистрированные сервисы.
        // FirewallHost — единственный владелец дескриптора перехвата,
        // поэтому он обязан лежать в контейнере, иначе каждый запрос
        // падал бы с 500 при попытке разрешить параметр.
        builder.Services.AddSingleton(host);

        var app = builder.Build();

        MapEndpoints(app, host);
        app.MapGet("/", () => Results.Content(Ui.Page, "text/html; charset=utf-8"));

        app.Lifetime.ApplicationStarted.Register(() =>
        {
            Console.WriteLine($"Веб-интерфейс: {url}");
            Console.WriteLine("Открыть в браузере: Start-Process " + url);
        });

        await app.RunAsync().ConfigureAwait(false);
    }

    private static void MapEndpoints(WebApplication app, FirewallHost host)
    {
        app.MapGet("/api/status", (FirewallHost h) => Results.Json(h.GetStatus(), Json));

        app.MapGet("/api/stats", (FirewallHost h) =>
            Results.Json(h.Engine?.GetStatus().Statistics ?? new TrafficStatistics().Snapshot(), Json));

        app.MapGet("/api/rules", (FirewallHost h) => Results.Json(new
        {
            defaultAction = h.CurrentRules.DefaultAction.ToString(),
            loadedAt = h.CurrentRules.LoadedAt,
            rules = h.CurrentRules.Rules.Select(r => new
            {
                r.Id,
                r.Name,
                action = r.Action.ToString(),
                r.Priority,
                r.Enabled,
                r.Protocol,
                direction = r.Direction.ToString(),
                r.SourceAddress,
                r.DestinationAddress,
                r.SourcePort,
                r.DestinationPort,
                r.Log,
                hitCount = r.HitCount,
                hitBytes = r.HitBytes,
            }),
        }, Json));

        app.MapGet("/api/logs", (FirewallHost h, int? tail) =>
        {
            var entries = h.Engine?.MemoryLog.Tail(tail ?? 100) ?? [];
            return Results.Json(entries.Select(e => new
            {
                timestamp = e.Timestamp,
                direction = e.Direction.ToString(),
                action = e.Action.ToString(),
                e.Protocol,
                e.SourceAddress,
                e.SourcePort,
                e.DestinationAddress,
                e.DestinationPort,
                e.PacketLength,
                e.RuleId,
                e.RuleName,
                e.Reason,
            }), Json);
        });

        app.MapPost("/api/rules", (FirewallHost h, RuleUpdateRequest request) =>
        {
            if (!Enum.TryParse<RuleAction>(request.DefaultAction, ignoreCase: true, out var action))
            {
                return Results.BadRequest(new { error = $"Неизвестное действие по умолчанию: {request.DefaultAction}" });
            }

            var rules = request.Rules.Select(r => new Rule
            {
                Name = r.Name,
                Action = Enum.TryParse<RuleAction>(r.Action, ignoreCase: true, out var a) ? a : RuleAction.Deny,
                Protocol = r.Protocol,
                Direction = Enum.TryParse<RuleDirection>(r.Direction, ignoreCase: true, out var d) ? d : RuleDirection.Any,
                SourceAddress = r.SourceAddress,
                DestinationAddress = r.DestinationAddress,
                SourcePort = r.SourcePort,
                DestinationPort = r.DestinationPort,
                Enabled = r.Enabled,
                Log = r.Log,
            }).ToList();

            if (!h.TrySaveRules(rules, action, out var error))
                return Results.BadRequest(new { error });

            return Results.Json(new { ok = true, ruleCount = rules.Count }, Json);
        });

        app.MapPost("/api/reload", (FirewallHost h) =>
        {
            bool ok = h.TryReloadRules(out var set);

            return ok
                ? Results.Json(new { ok = true, ruleCount = set?.Count ?? 0, warnings = h.LastWarnings }, Json)
                : Results.BadRequest(new { ok = false, error = h.LastError });
        });

        app.MapPost("/api/start", (FirewallHost h) =>
        {
            bool ok = h.TryStart();
            return ok ? Results.Json(new { ok = true }, Json)
                      : Results.BadRequest(new { ok = false, error = h.LastError });
        });

        app.MapPost("/api/stop", async (FirewallHost h) =>
        {
            await h.StopAsync().ConfigureAwait(false);
            return Results.Json(new { ok = true }, Json);
        });
    }

    public sealed class RuleUpdateRequest
    {
        public string DefaultAction { get; set; } = "Deny";
        public List<RuleItem> Rules { get; set; } = [];
    }

    public sealed class RuleItem
    {
        public string Name { get; set; } = string.Empty;
        public string Action { get; set; } = "Deny";
        public string Protocol { get; set; } = "Any";
        public string Direction { get; set; } = "Any";
        public string SourceAddress { get; set; } = "";
        public string DestinationAddress { get; set; } = "";
        public string SourcePort { get; set; } = "any";
        public string DestinationPort { get; set; } = "any";
        public bool Enabled { get; set; } = true;
        public bool Log { get; set; } = true;
    }
}

/// <summary>Статическая страница панели управления.</summary>
internal static class Ui
{
    public const string Page =
        """
        <!DOCTYPE html>
        <html lang="ru">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>NetGuard — панель управления</title>
        <style>
          :root {
            --bg: #14161a; --panel: #1c1f26; --panel-2: #232733;
            --line: #2f3542; --fg: #e8eaf0; --muted: #98a0b3;
            --allow: #2ea043; --deny: #d13c3c; --accent: #4c8dff;
          }
          * { box-sizing: border-box; }
          body { margin: 0; background: var(--bg); color: var(--fg);
                 font: 14px/1.5 "Segoe UI", system-ui, sans-serif; }
          header { display: flex; align-items: center; gap: 16px; flex-wrap: wrap;
                   padding: 14px 20px; background: var(--panel); border-bottom: 1px solid var(--line); }
          h1 { font-size: 17px; margin: 0; letter-spacing: .3px; }
          h2 { font-size: 14px; margin: 0 0 10px; color: var(--muted); font-weight: 600; }
          .grow { flex: 1; }
          .pill { padding: 3px 11px; border-radius: 999px; font-size: 12px; font-weight: 600; }
          .pill.run { background: rgba(46,160,67,.18); color: #56d364; border: 1px solid rgba(46,160,67,.5); }
          .pill.stop { background: rgba(209,60,60,.16); color: #f78166; border: 1px solid rgba(209,60,60,.45); }
          .pill.warn { background: rgba(210,153,34,.16); color: #e3b341; border: 1px solid rgba(210,153,34,.45); }
          button { background: var(--panel-2); color: var(--fg); border: 1px solid var(--line);
                   border-radius: 7px; padding: 7px 13px; cursor: pointer; font: inherit; }
          button:hover:not(:disabled) { border-color: var(--accent); }
          button:disabled { opacity: .45; cursor: not-allowed; }
          button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
          button.danger  { background: var(--deny); border-color: var(--deny); color: #fff; }
          main { padding: 18px 20px 40px; display: grid; gap: 16px;
                 grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); }
          section { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; }
          .wide { grid-column: 1 / -1; }
          .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px,1fr)); gap: 10px; }
          .card { background: var(--panel-2); border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; }
          .card b { display: block; font-size: 20px; font-weight: 600; }
          .card span { color: var(--muted); font-size: 12px; }
          table { width: 100%; border-collapse: collapse; font-size: 13px; }
          th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); }
          th { color: var(--muted); font-weight: 600; font-size: 12px; position: sticky; top: 0; background: var(--panel); }
          tbody tr:hover { background: var(--panel-2); }
          .scroll { max-height: 340px; overflow: auto; }
          .tag { padding: 1px 8px; border-radius: 5px; font-size: 11px; font-weight: 700; }
          .tag.allow { background: rgba(46,160,67,.2); color: #56d364; }
          .tag.deny  { background: rgba(209,60,60,.2); color: #f78166; }
          .muted { color: var(--muted); }
          code { background: var(--panel-2); padding: 1px 5px; border-radius: 4px; font-size: 12px; }
          input, select { background: var(--panel-2); color: var(--fg); border: 1px solid var(--line);
                          border-radius: 6px; padding: 5px 8px; font: inherit; font-size: 13px; }
          #msg { margin-left: auto; font-size: 13px; }
          .err { color: #f78166; } .ok { color: #56d364; }
        </style>
        </head>
        <body>
        <header>
          <h1>NetGuard</h1>
          <span id="state" class="pill stop">загрузка…</span>
          <span id="elev" class="pill warn"></span>
          <span id="msg"></span>
          <span class="grow"></span>
          <button id="btnStart" class="primary">Запустить</button>
          <button id="btnStop" class="danger">Остановить</button>
          <button id="btnReload">Перечитать rules.json</button>
        </header>

        <main>
          <section>
            <h2>Состояние</h2>
            <div class="cards" id="statCards"></div>
            <p class="muted" id="filterLine" style="margin:12px 0 0"></p>
            <p class="err" id="errLine" style="margin:6px 0 0"></p>
          </section>

          <section>
            <h2>Топ адресов (заблокировано / разрешено)</h2>
            <div class="scroll">
              <table><thead><tr><th>Адрес</th><th>Пакетов</th></tr></thead>
              <tbody id="topBody"></tbody></table>
            </div>
          </section>

          <section class="wide">
            <h2>Правила (порядок = приоритет, первое совпадение выигрывает)</h2>
            <div class="scroll">
              <table>
                <thead><tr>
                  <th>#</th><th>Действие</th><th>Имя</th><th>Протокол</th><th>Направление</th>
                  <th>Источник</th><th>Получатель</th><th>Порт→</th><th>Пакетов</th><th>Логировать</th>
                </tr></thead>
                <tbody id="rulesBody"></tbody>
              </table>
            </div>
          </section>

          <section class="wide">
            <h2>Последние события</h2>
            <div class="scroll">
              <table>
                <thead><tr>
                  <th>Время</th><th>Направление</th><th>Протокол</th><th>Источник</th>
                  <th>Получатель</th><th>Решение</th><th>Основание</th>
                </tr></thead>
                <tbody id="logBody"></tbody>
              </table>
            </div>
          </section>
        </main>

        <script>
        const $ = id => document.getElementById(id);
        const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
        const num = n => (n ?? 0).toLocaleString('ru-RU');
        const bytes = n => {
          const u = ['Б','КБ','МБ','ГБ']; let i = 0; n = n || 0;
          while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
          return n.toFixed(i ? 1 : 0) + ' ' + u[i];
        };
        let busy = false;
        let msgTimer = 0;

        function note(text, ok) {
          $('msg').textContent = text;
          $('msg').className = ok ? 'ok' : 'err';
          clearTimeout(msgTimer);
          // Успешное сообщение живёт 5 секунд, ошибка — до следующего
          // успешного обновления: иначе она «залипала» бы на экране
          // даже после восстановления связи с сервером.
          if (ok) msgTimer = setTimeout(() => { $('msg').textContent = ''; }, 5000);
        }

        async function api(path, opts) {
          const r = await fetch(path, opts);
          const body = await r.json().catch(() => ({}));
          if (!r.ok) throw new Error(body.error || ('HTTP ' + r.status));
          return body;
        }

        async function refresh() {
          let failed = false;

          try {
            const s = await api('/api/status');
            const running = s.state === 'Running';

            const pill = $('state');
            pill.textContent = ({Running:'работает',Stopped:'остановлен',Starting:'запуск…',
                                 Stopping:'остановка…',Failed:'ошибка'})[s.state] || s.state;
            pill.className = 'pill ' + (running ? 'run' : s.state === 'Failed' ? 'stop' : 'stop');

            $('elev').textContent = s.elevated ? 'администратор' : 'НЕ администратор';
            $('elev').className = 'pill ' + (s.elevated ? 'run' : 'warn');

            $('btnStart').disabled = running;
            $('btnStop').disabled  = !running;

            $('statCards').innerHTML = [
              ['Всего пакетов', num(s.statistics.total)],
              ['Разрешено', num(s.statistics.allowed)],
              ['Заблокировано', num(s.statistics.denied)],
              ['Данных принято', bytes(s.statistics.allowedBytes)],
              ['Данных отброшено', bytes(s.statistics.deniedBytes)],
              ['TCP / UDP', num(s.statistics.tcp) + ' / ' + num(s.statistics.udp)],
              ['ICMP', num(s.statistics.icmp)],
              ['Не разобрано', num(s.statistics.unparsed)],
              ['Правил', num(s.ruleCount)],
              ['По умолчанию', s.defaultAction],
            ].map(([k,v]) => '<div class="card"><b>' + esc(v) + '</b><span>' + esc(k) + '</span></div>').join('');

            $('filterLine').innerHTML = 'Фильтр перехвата: <code>' + esc(s.filter) + '</code>' +
              (s.logFile ? ' · журнал: <code>' + esc(s.logFile) + '</code>' : '');
            $('errLine').textContent = s.lastError ? 'Ошибка: ' + s.lastError : '';
          } catch (e) { failed = true; note('Статус недоступен: ' + e.message, false); }

          try {
            const r = await api('/api/rules');
            $('rulesBody').innerHTML = (r.rules || []).map(x =>
              '<tr>' +
              '<td>' + x.priority + '</td>' +
              '<td><span class="tag ' + (x.action === 'Allow' ? 'allow' : 'deny') + '">' + esc(x.action) + '</span></td>' +
              '<td>' + esc(x.name) + (x.enabled ? '' : ' <span class="muted">(выкл.)</span>') + '</td>' +
              '<td>' + esc(x.protocol) + '</td>' +
              '<td>' + esc(x.direction) + '</td>' +
              '<td><code>' + esc(x.sourceAddress || 'any') + ':' + esc(x.sourcePort) + '</code></td>' +
              '<td><code>' + esc(x.destinationAddress || 'any') + ':' + esc(x.destinationPort) + '</code></td>' +
              '<td class="muted">' + num(x.hitCount) + ' / ' + bytes(x.hitBytes) + '</td>' +
              '<td>' + (x.log ? 'да' : 'нет') + '</td>' +
              '</tr>').join('') || '<tr><td colspan="10" class="muted">Правил нет</td></tr>';
          } catch (e) { failed = true; note('Правила: ' + e.message, false); }

          try {
            const l = await api('/api/logs?tail=100');
            $('logBody').innerHTML = l.map(x =>
              '<tr>' +
              '<td>' + esc(x.timestamp.replace('T',' ').slice(0,23)) + '</td>' +
              '<td>' + esc(x.direction) + '</td>' +
              '<td>' + esc(x.protocol) + '</td>' +
              '<td><code>' + esc(x.sourceAddress) + ':' + x.sourcePort + '</code></td>' +
              '<td><code>' + esc(x.destinationAddress) + ':' + x.destinationPort + '</code></td>' +
              '<td><span class="tag ' + (x.action === 'Allow' ? 'allow' : 'deny') + '">' + esc(x.action) + '</span></td>' +
              '<td class="muted">' + esc(x.reason) + '</td>' +
              '</tr>').join('') || '<tr><td colspan="7" class="muted">Событий нет</td></tr>';
          } catch (e) { failed = true; note('Журнал: ' + e.message, false); }

          // Все запросы прошли — снимаем «залипшее» сообщение об ошибке.
          if (!failed && $('msg').className === 'err') $('msg').textContent = '';
        }

        async function act(path, label) {
          if (busy) return; busy = true;
          try { await api(path, { method: 'POST' }); note(label + ' — готово', true); }
          catch (e) { note(label + ' — ошибка: ' + e.message, false); }
          finally { busy = false; refresh(); }
        }

        $('btnStart').onclick = () => act('/api/start', 'Запуск');
        $('btnStop').onclick  = () => act('/api/stop', 'Остановка');
        $('btnReload').onclick = () => act('/api/reload', 'Перечитывание правил');

        refresh();
        setInterval(refresh, 2000);
        </script>
        </body>
        </html>
        """;
}