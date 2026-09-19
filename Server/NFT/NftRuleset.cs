namespace RouterNftConfig.Server.NFT;

public sealed record NftRuleset(
    NftMetainfo? Metainfo,
    IReadOnlyList<NftTable> Tables,
    IReadOnlyList<NftChain> Chains,
    IReadOnlyList<NftSet> Sets,
    IReadOnlyList<NftRule> Rules,
    IReadOnlyList<NftUnknownObject> UnknownObjects)
{
    public NftSet? FindSet(NftSetRef reference) => Sets.FirstOrDefault(x =>
        x.Family == reference.Family && x.Table == reference.Table && x.Name == reference.Name);

    public NftChain? FindChain(NftChainRef reference) => Chains.FirstOrDefault(x =>
        x.Family == reference.Family && x.Table == reference.Table && x.Name == reference.Name);
}