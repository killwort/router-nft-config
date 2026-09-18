using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace RouterNftConfig.Server.NFT;

/// <summary>Abstraction over an nftables ruleset.</summary>
public interface INftablesClient
{
    /// <summary>
    /// Executes a textual nft batch. The Linux implementation applies it atomically through
    /// <c>nft -f -</c>. The file-backed mock records arbitrary batches but does not parse them.
    /// </summary>
    Task<NftExecutionResult> ExecuteBatchAsync(
        string batch,
        CancellationToken cancellationToken = default);

    /// <summary>Runs <c>nft -j list ruleset</c> or reads the mock state file.</summary>
    Task<NftRuleset> ListRulesetAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically flushes a named set and adds the supplied elements. The set must already exist.
    /// </summary>
    Task ReplaceSetAsync(
        NftSetRef set,
        IEnumerable<NftSetElement> elements,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically replaces all rules in an existing chain. The chain declaration, hook and policy
    /// are preserved. Rule expressions are the part following <c>add rule family table chain</c>.
    /// </summary>
    Task ReplaceChainAsync(
        NftChainRef chain,
        IEnumerable<NftRuleDefinition> rules,
        CancellationToken cancellationToken = default);
}