using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;

namespace RouterNftConfig.Server.ARP;

internal static class ArpJson
{
    public static IReadOnlyList<ArpMapping> ParseIpNeighbour(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
            throw new JsonException("Expected ip -j neighbour output to be a JSON array.");

        var result = new List<ArpMapping>();
        foreach (var item in document.RootElement.EnumerateArray())
        {
            var destination = String(item, "dst");
            var linkAddress = String(item, "lladdr");
            if (destination is null || linkAddress is null) continue;
            if (!IPAddress.TryParse(destination, out var inet) ||
                inet.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                continue;
            if (!TryParseEther(linkAddress, out var ether)) continue;

            result.Add(new ArpMapping(
                ether,
                inet,
                String(item, "dev") ?? string.Empty,
                Strings(item, "state")));
        }
        return result;
    }

    public static IReadOnlyList<ArpMapping> ParseMock(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
            throw new JsonException("ARP mock file must contain a JSON array.");

        var result = new List<ArpMapping>();
        foreach (var item in document.RootElement.EnumerateArray())
        {
            var inetText = RequiredString(item, "inet");
            var etherText = RequiredString(item, "ether");
            if (!IPAddress.TryParse(inetText, out var inet) ||
                inet.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                throw new JsonException($"'{inetText}' is not an IPv4 address.");
            if (!TryParseEther(etherText, out var ether))
                throw new JsonException($"'{etherText}' is not a 6-byte Ethernet address.");

            result.Add(new ArpMapping(
                ether,
                inet,
                String(item, "interface") ?? string.Empty,
                Strings(item, "state")));
        }
        return result;
    }

    private static bool TryParseEther(string value, out PhysicalAddress address)
    {
        var compact = value.Replace(":", string.Empty, StringComparison.Ordinal)
            .Replace("-", string.Empty, StringComparison.Ordinal);
        if (compact.Length != 12 || !compact.All(Uri.IsHexDigit))
        {
            address = PhysicalAddress.None;
            return false;
        }
        address = PhysicalAddress.Parse(compact);
        return address.GetAddressBytes().Length == 6;
    }

    private static string RequiredString(JsonElement item, string property) =>
        String(item, property) ?? throw new JsonException($"Missing string property '{property}'.");

    private static string? String(JsonElement item, string property) =>
        item.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static IReadOnlyList<string> Strings(JsonElement item, string property)
    {
        if (!item.TryGetProperty(property, out var value)) return [];
        if (value.ValueKind == JsonValueKind.String) return [value.GetString()!];
        if (value.ValueKind != JsonValueKind.Array) return [];
        return value.EnumerateArray()
            .Where(x => x.ValueKind == JsonValueKind.String)
            .Select(x => x.GetString()!)
            .ToArray();
    }
}
