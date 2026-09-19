using System.Text.Json;

namespace RouterNftConfig.Server.NFT;

public sealed record NftTable(
    NftFamily Family,
    string Name,
    long? Handle,
    IReadOnlyList<string> Flags,
    JsonElement Raw);