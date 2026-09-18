namespace RouterNftConfig.Server.NFT;

public readonly record struct NftSetRef(NftFamily Family, string Table, string Name)
{
    internal string ToNftPath() =>
        $"{Family.ToNftString()} {NftSyntax.Identifier(Table)} {NftSyntax.Identifier(Name)}";
}