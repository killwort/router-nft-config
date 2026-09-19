using System.Text.Json;

namespace RouterNftConfig.Server.NFT;

internal sealed record NftRuleSnapshot(
    IReadOnlyList<JsonElement> Expressions,
    string? Comment,
    string? MockExpression);