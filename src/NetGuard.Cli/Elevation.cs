using System.ComponentModel;
using System.Diagnostics;

namespace NetGuard.Cli;

/// <summary>
/// Самостоятельное повышение прав до администратора.
///
/// Зачем это нужно: перехват пакетов выполняется драйвером в ядре, поэтому
/// обычный запуск (в том числе двойным кликом по .exe) всегда завершается
/// ошибкой «недостаточно прав». Вместо того чтобы требовать от пользователя
/// разбираться с командной строкой, программа сама перезапускается через
/// UAC — после этого двойной клик по файлу работает как ожидается.
/// </summary>
internal static class Elevation
{
    /// <summary>
    /// Метка, защищающая от бесконечного перезапуска. Если пользователь
    /// отклонил запрос UAC и среда вернула неповышенный процесс,
    /// программа не должна просить права снова.
    /// </summary>
    private const string AttemptMarker = "NETGUARD_ELEVATION_ATTEMPTED";

    /// <summary>
    /// Перезапускает текущий процесс с повышенными правами, сохраняя аргументы.
    /// Возвращает true, если новый процесс был запущен.
    /// </summary>
    public static bool TryRelaunchElevated(string[] args)
    {
        string? executable = Environment.ProcessPath;

        if (string.IsNullOrEmpty(executable))
            return false;

        // Уже пробовали — второй раз не спрашиваем.
        if (Environment.GetEnvironmentVariable(AttemptMarker) == "1")
            return false;

        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = true,

            // runas — стандартный способ запросить повышение прав в Windows:
            // пользователю показывается окно UAC.
            Verb = "runas",
            WorkingDirectory = AppContext.BaseDirectory,
        };

        foreach (string arg in args)
            startInfo.ArgumentList.Add(arg);

        startInfo.Environment[AttemptMarker] = "1";

        try
        {
            Process.Start(startInfo);
            return true;
        }
        catch (Win32Exception)
        {
            // HRESULT 1223 — пользователь закрыл окно UAC, отказав в повышении прав.
            return false;
        }
        catch (Exception)
        {
            return false;
        }
    }
}