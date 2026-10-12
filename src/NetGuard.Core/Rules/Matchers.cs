using System.Net;
using System.Net.Sockets;

namespace NetGuard.Core.Rules;

/// <summary>
/// Подсеть в нотации CIDR: адрес + длина префикса.
/// Поддерживает IPv4 и IPv6; сравнение идёт побайтово по маске,
/// поэтому не зависит от представления адреса.
/// </summary>
public sealed class CidrBlock
{
    private readonly byte[] _network;

    public IPAddress Address { get; }
    public int PrefixLength { get; }
    public bool IsAny { get; }
    public AddressFamily Family { get; }

    public CidrBlock(IPAddress address, int prefixLength)
    {
        ArgumentNullException.ThrowIfNull(address);

        Address = address;
        Family = address.AddressFamily;

        int maxPrefix = Family == AddressFamily.InterNetwork ? 32 : 128;
        if (prefixLength < 0 || prefixLength > maxPrefix)
        {
            throw new ArgumentOutOfRangeException(
                nameof(prefixLength),
                $"Префикс /{prefixLength} недопустим для {Family} (0…{maxPrefix}).");
        }

        PrefixLength = prefixLength;
        _network = address.GetAddressBytes();

        IsAny = prefixLength == 0;
    }

    /// <summary>Подсеть, совпадающая с любым адресом.</summary>
    public static CidrBlock Any(AddressFamily family) => new(
        family == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);

    /// <summary>
    /// Разбирает "10.0.0.0/8", "192.168.1.1" (префикс по умолчанию — полный)
    /// и "::1", "2001:db8::/32".
    /// </summary>
    public static bool TryParse(string? text, out CidrBlock? block)
    {
        block = null;

        if (string.IsNullOrWhiteSpace(text))
            return false;

        string value = text.Trim();

        int slash = value.IndexOf('/');
        string addressPart = slash >= 0 ? value[..slash] : value;

        if (!IPAddress.TryParse(addressPart, out var address))
            return false;

        // Приводим IPv4-mapped IPv6 (::ffff:10.0.0.1) к IPv4 — иначе
        // сравнение с IPv4-правилом не совпало бы никогда.
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        int prefix;
        if (slash >= 0)
        {
            if (!int.TryParse(value[(slash + 1)..], out prefix))
                return false;
        }
        else
        {
            prefix = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        }

        try
        {
            block = new CidrBlock(address, prefix);
            return true;
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    public bool Contains(IPAddress? candidate)
    {
        if (candidate is null)
            return false;

        if (candidate.IsIPv4MappedToIPv6)
            candidate = candidate.MapToIPv4();

        // Сравнивать подсеть IPv4 с адресом IPv6 бессмысленно.
        if (candidate.AddressFamily != Family)
            return false;

        if (IsAny)
            return true;

        byte[] bytes = candidate.GetAddressBytes();
        int fullBytes = PrefixLength / 8;
        int remainingBits = PrefixLength % 8;

        for (int i = 0; i < fullBytes; i++)
        {
            if (_network[i] != bytes[i])
                return false;
        }

        if (remainingBits == 0)
            return true;

        int mask = (byte)(0xFF << (8 - remainingBits));
        return (_network[fullBytes] & mask) == (bytes[fullBytes] & mask);
    }

    public override string ToString() => $"{Address}/{PrefixLength}";

    /// <summary>
    /// Могут ли две подсети пересекаться. Используется для поиска
    /// перекрывающихся правил: сравнивать нужно по общему префиксу,
    /// иначе подсети /8 и /24 внутри неё ошибочно считались бы
    /// непересекающимися.
    /// </summary>
    public bool Intersects(CidrBlock? other)
    {
        if (other is null || IsAny || other.IsAny)
            return true;

        // Подсети разных версий не пересекаются.
        if (Family != other.Family)
            return false;

        byte[] mine = _network;
        byte[] theirs = other._network;

        int shorter = Math.Min(PrefixLength, other.PrefixLength);
        int fullBytes = shorter / 8;
        int remainingBits = shorter % 8;

        for (int i = 0; i < fullBytes; i++)
        {
            if (mine[i] != theirs[i])
                return false;
        }

        if (remainingBits == 0)
            return true;

        int mask = (byte)(0xFF << (8 - remainingBits));
        return (mine[fullBytes] & mask) == (theirs[fullBytes] & mask);
    }
}

/// <summary>
/// Диапазон портов: один порт, диапазон или «любой».
/// Границы включаются в диапазон.
/// </summary>
public readonly record struct PortRange(ushort Start, ushort End)
{
    /// <summary>Пустой диапазон — совпадает с любым портом.</summary>
    public static PortRange Any { get; } = new(0, 0);

    public bool IsAny => Start == 0 && End == 0;
    public bool IsSingle => Start == End && Start != 0;

    public static PortRange Single(ushort port) => new(port, port);

    public static PortRange Range(ushort start, ushort end) =>
        start <= end ? new PortRange(start, end) : new PortRange(end, start);

    public bool Contains(ushort port) => IsAny || (port >= Start && port <= End);

    /// <summary>
    /// Разбирает "80", "8000-8080", "1024-", "any", "any-1024".
    /// Для портов вида "80,443,8000-8080" используйте <see cref="CompositePortSet"/>.
    /// </summary>
    public static bool TryParse(string? text, out PortRange range)
    {
        range = Any;

        if (string.IsNullOrWhiteSpace(text))
            return false;

        string value = text.Trim();

        if (value.Equals("any", StringComparison.OrdinalIgnoreCase) ||
            value == "*" || value == "-")
        {
            range = Any;
            return true;
        }

        int dash = value.IndexOf('-');
        if (dash < 0)
        {
            if (!ushort.TryParse(value, out ushort single))
                return false;

            range = Single(single);
            return true;
        }

        string left = value[..dash].Trim();
        string right = value[(dash + 1)..].Trim();

        // Открытый диапазон "1024-" или "-1024".
        ushort start = 0;
        ushort end = 0;

        if (left.Length == 0)
        {
            end = ushort.TryParse(right, out ushort onlyEnd) ? onlyEnd : (ushort)0;
            if (end == 0 && !ushort.TryParse(right, out _))
                return false;

            range = new PortRange(0, end);
            return true;
        }

        if (right.Length == 0)
        {
            if (!ushort.TryParse(left, out start))
                return false;

            range = new PortRange(start, ushort.MaxValue);
            return true;
        }

        if (!ushort.TryParse(left, out start) || !ushort.TryParse(right, out end))
            return false;

        range = Range(start, end);
        return true;
    }

    public override string ToString() =>
        IsAny ? "any" : IsSingle ? Start.ToString() : $"{Start}-{End}";
}

/// <summary>
/// Набор диапазонов портов для записи вида "80,443,8000-8080".
/// Правила с набором проверяются, только если ни один одиночный диапазон
/// не подошёл, — это позволяет писать простые правила без набора.
/// </summary>
public sealed class CompositePortSet
{
    private readonly PortRange[] _ranges;

    public CompositePortSet(PortRange[] ranges) => _ranges = ranges ?? [];

    public IReadOnlyList<PortRange> Ranges => _ranges;

    public bool IsEmpty => _ranges.Length == 0;

    public bool Contains(ushort port)
    {
        foreach (var range in _ranges)
        {
            if (range.Contains(port))
                return true;
        }

        return false;
    }

    /// <summary>Разбирает список "80,443,8000-8080" либо единственное значение.</summary>
    public static bool TryParse(string? text, out CompositePortSet? set)
    {
        set = null;

        if (string.IsNullOrWhiteSpace(text))
            return false;

        var ranges = new List<PortRange>();

        foreach (string part in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!PortRange.TryParse(part, out var range))
                return false;

            ranges.Add(range);
        }

        if (ranges.Count == 0)
            return false;

        set = new CompositePortSet(ranges.ToArray());
        return true;
    }

    public override string ToString() =>
        _ranges.Length == 0 ? "any" : string.Join(',', _ranges.Select(r => r.ToString()));

    /// <summary>Могут ли два набора портов пересекаться (null или пустой = «любой»).</summary>
    public static bool MayIntersect(CompositePortSet? a, CompositePortSet? b)
    {
        if (a is null || a.IsEmpty || b is null || b.IsEmpty)
            return true;

        foreach (var x in a._ranges)
        {
            foreach (var y in b._ranges)
            {
                if (x.IsAny || y.IsAny)
                    return true;

                if (x.Start <= y.End && y.Start <= x.End)
                    return true;
            }
        }

        return false;
    }
}