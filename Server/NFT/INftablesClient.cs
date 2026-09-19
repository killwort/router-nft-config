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
    /// Creates a builder which queues mutating operations and applies them in one atomic batch.
    /// </summary>
    INftablesBatch CreateBatch();
}