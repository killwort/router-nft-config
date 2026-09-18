using System.Text.Json;

namespace RouterNftConfig.Server.NFT;

public sealed record NftUnknownObject(string Kind, JsonElement Raw);