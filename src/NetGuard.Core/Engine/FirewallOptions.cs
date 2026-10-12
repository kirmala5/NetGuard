using System.Net.Sockets;
using System.Security.Principal;

namespace NetGuard.Core.Engine;

/// <summary>
/// Параметры работы движка и константы, общие для CLI и веб-интерфейса.
/// </summary>
public static class FirewallOptions
{
    /// <summary>
    /// Фильтр перехвата по умолчанию: весь IP/IPv6 трафик в обе стороны,
    /// кроме loopback и multicast.
    ///
    /// Loopback исключён намеренно: перехваченный пакет loopback
    /// возвращается в стек повторно и может зациклиться, а диагностировать
    /// такое поведение тяжелее, чем просто не захватывать его.
    /// Multicast/broadcast отфильтрованы, чтобы не мешать служебному
    /// трафику (mDNS, SSDP, DHCP).
    /// </summary>
    public const string DefaultFilter =
        "(outbound or inbound) and (ip or ipv6) and not loopback and not multicast";

    /// <summary>Фильтр с захватом loopback — для отладки на одной машине.</summary>
    public const string LoopbackFilter =
        "(outbound or inbound) and (ip or ipv6)";

    /// <summary>Максимальный размер одного перехваченного пакета ( jumbo не поддерживается).</summary>
    public const int MaxPacketSize = 65535;

    /// <summary>Проверка прав администратора: без них драйвер WinDivert не загрузится.</summary>
    public static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Текст с объяснением, что делать без прав администратора.</summary>
    public static string ElevationHint =>
        "Файрволу нужны права администратора: драйвер перехвата пакетов " +
        "загружается в ядро ОС. Запустите программу в консоли от имени " +
        "администратора (правый клик по ярлыку → «Запуск от имени администратора» " +
        "или выполните в PowerShell: Start-Process -Verb RunAs).";
}