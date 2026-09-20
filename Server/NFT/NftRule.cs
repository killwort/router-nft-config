using System.Text.Json;

namespace RouterNftConfig.Server.NFT;

public sealed record NftRule(
    NftFamily Family,
    string Table,
    string Chain,
    long? Handle,
    long? Index,
    string? Comment,
    IReadOnlyList<JsonElement> Expressions,
    JsonElement Raw) : IReferencedObject
{
    public string Name => Chain;
};