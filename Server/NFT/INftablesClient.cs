using System.Threading;
using System.Threading.Tasks;

namespace RouterNftConfig.Server.NFT;

/// <summary>Abstraction over an nftables ruleset.</summary>
public interface INftablesClient
{
    /// <summary>
    /// Executes a textual nft batch atomically through <c>nft -f -</c>.
    /// </summary>
    Task<NftExecutionResult> ExecuteBatchAsync(
        string batch,
        CancellationToken cancellationToken = default);

    /// <summary>Runs <c>nft -j list ruleset</c>.</summary>
    Task<NftRuleset> ListRulesetAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a builder which queues mutating operations and applies them in one atomic batch.
    /// </summary>
    INftablesBatch CreateBatch();
}