using System;
using System.Collections.Generic;

namespace RouterNftConfig.Server.NFT;

/// <summary>Convenience entry points for starting a mutation batch from a client.</summary>
public static class NftablesClientBatchExtensions
{
    public static INftablesBatch CreateSet(
        this INftablesClient client,
        NftSetRef set,
        NftSetDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(client);
        return client.CreateBatch().CreateSet(set, definition);
    }

    public static INftablesBatch DeleteSet(this INftablesClient client, NftSetRef set)
    {
        ArgumentNullException.ThrowIfNull(client);
        return client.CreateBatch().DeleteSet(set);
    }

    public static INftablesBatch AddSetElement(
        this INftablesClient client,
        NftSetRef set,
        NftSetElement element)
    {
        ArgumentNullException.ThrowIfNull(client);
        return client.CreateBatch().AddSetElement(set, element);
    }

    public static INftablesBatch CreateChain(this INftablesClient client, NftChainRef chain)
    {
        ArgumentNullException.ThrowIfNull(client);
        return client.CreateBatch().CreateChain(chain);
    }

    public static INftablesBatch CreateChain(
        this INftablesClient client,
        NftChainRef chain,
        NftChainDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(client);
        return client.CreateBatch().CreateChain(chain, definition);
    }

    public static INftablesBatch ReplaceSet(
        this INftablesClient client,
        NftSetRef set,
        IEnumerable<NftSetElement> elements)
    {
        ArgumentNullException.ThrowIfNull(client);
        return client.CreateBatch().ReplaceSet(set, elements);
    }

    public static INftablesBatch ReplaceChain(
        this INftablesClient client,
        NftChainRef chain,
        IEnumerable<NftRuleDefinition> rules)
    {
        ArgumentNullException.ThrowIfNull(client);
        return client.CreateBatch().ReplaceChain(chain, rules);
    }

    public static INftablesBatch ReplaceChain(
        this INftablesClient client,
        NftChainRef chain,
        IEnumerable<NftRule> rules)
    {
        ArgumentNullException.ThrowIfNull(client);
        return client.CreateBatch().ReplaceChain(chain, rules);
    }
}
