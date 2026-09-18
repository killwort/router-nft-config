using System.Text.Json;

namespace RouterNftConfig.Server.NFT;

public sealed record NftChain(
    NftFamily Family,
    string Table,
    string Name,
    long? Handle,
    string? Type,
    string? Hook,
    int? Priority,
    string? Device,
    string? Policy,
    string? Comment,
    JsonElement Raw);