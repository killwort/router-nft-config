using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace RouterNftConfig.Server.NFT;

public sealed record NftSet(
    NftFamily Family,
    string Table,
    string Name,
    long? Handle,
    IReadOnlyList<string> Types,
    IReadOnlyList<string> Flags,
    IReadOnlyList<JsonElement> Elements,
    long? TimeoutSeconds,
    long? GcIntervalSeconds,
    int? Size,
    string? Comment,
    JsonElement Raw)
{
    public bool IsEtherAddressSet => Types.Count == 1 && Types[0] == "ether_addr";
    public bool IsInternetAddressSet => Types.Count == 1 && Types[0] is "ipv4_addr" or "ipv6_addr";

    public IEnumerable<string> SimpleStringElements() => Elements
        .Where(x => x.ValueKind == JsonValueKind.String)
        .Select(x => x.GetString()!);
}