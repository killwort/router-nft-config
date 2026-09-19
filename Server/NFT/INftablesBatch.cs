namespace RouterNftConfig.Server.NFT;

/// <summary>
/// A single-use builder for mutating nftables operations. Nothing is applied before
/// <see cref="ExecuteAsync"/> is called.
/// </summary>
public interface INftablesBatch
{
    int Count { get; }

    /// <summary>Queues strict creation of a named set.</summary>
    INftablesBatch CreateSet(NftSetRef set, NftSetDefinition definition);

    /// <summary>Queues deletion of an existing named set.</summary>
    INftablesBatch DeleteSet(NftSetRef set);

    /// <summary>Queues strict creation of a chain.</summary>
    INftablesBatch CreateChain(NftChainRef chain);

    /// <summary>Queues strict creation of a regular or base chain.</summary>
    INftablesBatch CreateChain(NftChainRef chain, NftChainDefinition definition);

    /// <summary>Queues replacement of all elements in an existing named set.</summary>
    INftablesBatch ReplaceSet(NftSetRef set, IEnumerable<NftSetElement> elements);

    /// <summary>
    /// Queues replacement of all rules in an existing chain while preserving its declaration.
    /// </summary>
    INftablesBatch ReplaceChain(NftChainRef chain, IEnumerable<NftRuleDefinition> rules);

    /// <summary>
    /// Queues replacement using rules returned by <see cref="INftablesClient.ListRulesetAsync"/>.
    /// JSON expressions are rendered to native nft syntax. Rule handles, indices and original
    /// chain locations are deliberately not copied.
    /// </summary>
    INftablesBatch ReplaceChain(NftChainRef chain, IEnumerable<NftRule> rules);

    /// <summary>Executes all queued operations once, as a single transaction.</summary>
    Task<NftExecutionResult> ExecuteAsync(CancellationToken cancellationToken = default);
}
