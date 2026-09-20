namespace RouterNftConfig.Server.NFT;

public readonly record struct NftChainRef(NftFamily Family, string Table, string Name) : IReferencedObject
{
    internal string ToNftPath() =>
        $"{Family.ToNftString()} {NftSyntax.Identifier(Table)} {NftSyntax.Identifier(Name)}";
}